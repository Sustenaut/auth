package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.Details;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

/**
 * Event listener {@value #PROVIDER_ID} (family realm, eventsListeners): emails the person when a
 * passkey is added to their account, the first one included. It reacts to UPDATE_CREDENTIAL with
 * credential_type webauthn-passwordless, which Keycloak's webauthn-register-passwordless required
 * action sends on success, however it was started: the invitation link, the offer after an email
 * sign-in, or an app asking for it (kc_action). Which passkeys get a notice is
 * {@link #NOTICE_FROM}, counted after the event.
 *
 * <p>The email says when (UTC), roughly on what (from the browser's User-Agent) and whom to
 * contact if it wasn't them: in the words of the domain that invited the person (TenantEmail;
 * its help contact) when it has settings, else neutral ones. A failure to send is logged and
 * never stops the passkey being added.
 */
public class PasskeyNotice implements EventListenerProvider, EventListenerProviderFactory {

    public static final String PROVIDER_ID = "sustenaut-passkey-notice";
    private static final Logger LOG = Logger.getLogger(PasskeyNotice.class);
    private static final DateTimeFormatter READABLE =
            DateTimeFormatter.ofPattern("EEEE d MMMM yyyy, HH:mm 'UTC'", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    /** The account's passkey count (after the new one) from which a notice is sent: 1 = every passkey, 2 = all but the first. */
    static final int NOTICE_FROM = 1;

    private final KeycloakSession session;

    public PasskeyNotice() {
        this(null);
    }

    PasskeyNotice(KeycloakSession session) {
        this.session = session;
    }

    /** Whether the event is a passkey added to someone's account. */
    static boolean passkeyAdded(Event event) {
        return event.getType() == EventType.UPDATE_CREDENTIAL && event.getError() == null && event.getUserId() != null
                && event.getDetails() != null
                && WebAuthnCredentialModel.TYPE_PASSWORDLESS.equals(event.getDetails().get(Details.CREDENTIAL_TYPE));
    }

    @Override
    public void onEvent(Event event) {
        if (!passkeyAdded(event)) {
            return;
        }
        RealmModel realm = session.getContext().getRealm();
        UserModel user = realm == null ? null : session.users().getUserById(realm, event.getUserId());
        if (user == null || user.getEmail() == null || !user.isEnabled()) {
            return;
        }
        long passkeys = user.credentialManager()
                .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS).count();
        if (passkeys < NOTICE_FROM) {
            return;
        }
        String agent = session.getContext().getRequestHeaders() == null ? null
                : session.getContext().getRequestHeaders().getHeaderString("User-Agent");
        Instant when = Instant.ofEpochMilli(event.getTime()).truncatedTo(ChronoUnit.SECONDS);
        try {
            TenantEmail mail = new TenantEmail(session, tenant(session, realm, user, event.getClientId()));
            mail.setUser(user);
            String name = mail.tenantName();
            Map<String, Object> body = new HashMap<>(Map.of(
                    "email", user.getEmail(),
                    "addedUtc", when.toString(),
                    "addedReadable", READABLE.format(when),
                    "device", device(agent)));
            mail.sendTenant(name == null ? "familyPasskeySubject" : "familyPasskeySubjectFor",
                    name == null ? List.of() : List.of(name), "family-passkey-added.ftl", body);
            LOG.infof("passkey notice: sent (passkey %d of the account)", passkeys);
        } catch (Exception e) {
            LOG.warnf(e, "passkey notice: could not email the account's owner");
        }
    }

    /**
     * The domain whose words the notice uses: of the domains that invited the person, the one the
     * passkey was added through if it is one of them, else the first; only an active domain with
     * settings (a display name) counts. Null for none: neutral wording.
     */
    static ClientModel tenant(KeycloakSession session, RealmModel realm, UserModel user, String clientId) {
        for (String domain : candidates(user.getAttributeStream(INVITED_BY).toList(), clientId)) {
            ClientModel client = session.clients().getClientByClientId(realm, domain);
            if (client != null && client.isEnabled() && "active".equals(client.getAttribute(STATE))
                    && TenantEmail.tenantAttributes(client).containsKey("tenantName")) {
                return client;
            }
        }
        return null;
    }

    /** The inviting domains in the order they are tried: the event's client first, if it is one. */
    static List<String> candidates(List<String> invitedBy, String clientId) {
        List<String> out = new ArrayList<>();
        if (clientId != null && invitedBy.contains(clientId)) {
            out.add(clientId);
        }
        invitedBy.stream().filter(d -> !out.contains(d)).forEach(out::add);
        return out;
    }

    /** A rough "browser on system" from a User-Agent, e.g. "Chrome on Android"; "an unknown device" if unclear. */
    static String device(String agent) {
        if (agent == null || agent.isBlank()) {
            return "an unknown device";
        }
        String browser = agent.contains("Edg/") ? "Edge"
                : agent.contains("OPR/") ? "Opera"
                : agent.contains("SamsungBrowser/") ? "Samsung Internet"
                : agent.contains("Firefox/") || agent.contains("FxiOS/") ? "Firefox"
                : agent.contains("Chrome/") || agent.contains("CriOS/") ? "Chrome"
                : agent.contains("Safari/") ? "Safari"
                : null;
        String system = agent.contains("iPhone") ? "an iPhone"
                : agent.contains("iPad") ? "an iPad"
                : agent.contains("Android") ? "Android"
                : agent.contains("CrOS") ? "ChromeOS"
                : agent.contains("Windows") ? "Windows"
                : agent.contains("Mac OS X") || agent.contains("Macintosh") ? "a Mac"
                : agent.contains("Linux") ? "Linux"
                : null;
        if (browser == null && system == null) {
            return "an unknown device";
        }
        if (browser == null) {
            return "a browser on " + system;
        }
        return system == null ? browser : browser + " on " + system;
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {}

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new PasskeyNotice(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
