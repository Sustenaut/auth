package eu.sustenaut.auth;

import java.time.Instant;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Event listener "sustenaut-sign-in" (realm/family.json, eventsListeners): on a person's first
 * sign-in, by whatever method, records when on the account ({@link AppRegistration#SIGNED_IN}).
 * GET /app-registration/{domain}/people reads it: signed in once = "active". The domains that
 * invited the person are told, if they asked to be (SignInNotice). Later sign-ins change
 * nothing (no write, no notice per sign-in).
 */
public class SignInRecorder implements EventListenerProvider, EventListenerProviderFactory {

    public static final String PROVIDER_ID = "sustenaut-sign-in";
    private static final Logger LOG = Logger.getLogger(SignInRecorder.class);

    private final KeycloakSession session;

    public SignInRecorder() {
        this(null);
    }

    private SignInRecorder(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() != EventType.LOGIN || event.getUserId() == null || session == null) {
            return;
        }
        // Keycloak calls listeners in the sign-in's own transaction (EventBuilder.send), with the
        // session it made us with: write through it, committed with the sign-in.
        RealmModel realm = session.realms().getRealm(event.getRealmId());
        UserModel user = realm == null ? null : session.users().getUserById(realm, event.getUserId());
        if (user == null) {
            LOG.warnf("sign-in recorder: no user %s in realm %s", event.getUserId(), event.getRealmId());
        } else if (user.getFirstAttribute(AppRegistration.SIGNED_IN) == null) {
            long now = Instant.now().getEpochSecond();
            user.setSingleAttribute(AppRegistration.SIGNED_IN, Long.toString(now));
            LOG.debugf("sign-in recorder: first sign-in of %s recorded", user.getId());
            SignInNotice.afterCommit(session, realm, user, now);
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {}

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new SignInRecorder(session);
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
