package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * "Remove my access": a person leaves a registered domain themselves. Application-initiated
 * only (kc_action=sustenaut-leave, with max_age=300 so the sign-in is fresh); never a default
 * action. The domain is the client the person signed in to (client id = the domain, an active
 * registration). A page in the family theme (family-leave.ftl) says what goes; confirming runs
 * FamilyRemoval.leave and goes back to the app's redirect URI with its state and
 * kc_action_status=success but no code (there is no session to give it); cancelling goes back
 * with a code as usual and kc_action_status=cancelled, nothing changed (the button is
 * Keycloak's own cancel-aia). Someone the domain did not invite sees that there is nothing to
 * remove, with only the way back (cancelled). A client that is not a domain's goes straight
 * back (kc_action_status=error). An app can send this flow to a page of its own (example.net:
 * share.example.net/left) that reads the status.
 */
public class LeaveDomainAction implements RequiredActionProvider, RequiredActionFactory {

    public static final String PROVIDER_ID = "sustenaut-leave";
    private static final Logger LOG = Logger.getLogger(LeaveDomainAction.class);

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {}

    /** The client signed in to, if it is a registered domain's active client; else null. */
    static ClientModel domainOf(RequiredActionContext context) {
        ClientModel client = context.getAuthenticationSession().getClient();
        return notADomain(client, domains(context.getRealm())) == null ? client : null;
    }

    /** Why the client is not a registered domain's active client (for the log); null if it is. */
    static String notADomain(ClientModel client, java.util.List<String> domains) {
        if (client == null) return "no client";
        if (!client.isEnabled()) return "client switched off";
        if (!"active".equals(client.getAttribute(STATE))) return "client not an active registration";
        if (!client.getClientId().equals(client.getAttribute(DOMAIN))) return "client id is not its domain";
        if (!domains.contains(client.getClientId())) return "domain not allowed in this realm";
        return null;
    }

    static boolean invited(RequiredActionContext context, ClientModel client) {
        return context.getUser().getAttributeStream(INVITED_BY).anyMatch(client.getClientId()::equals);
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        ClientModel client = domainOf(context);
        if (client == null) {
            ClientModel asked = context.getAuthenticationSession().getClient();
            LOG.infof("leave: skipped for client %s: %s", asked == null ? "-" : asked.getClientId(),
                    notADomain(asked, domains(context.getRealm())));
            context.ignore(); // back to the app (kc_action_status=error), nothing changed
            return;
        }
        if (!invited(context, client)) {
            LOG.infof("leave: %s: the account is not marked as invited by it; nothing to remove", client.getClientId());
            // Signed in, but not one of the domain's people (an admin's invitation, say): nothing to take.
            context.challenge(context.form()
                    .setAttribute("leaveName", nameOf(client))
                    .setAttribute("leaveNothing", true)
                    .createForm("family-leave.ftl"));
            return;
        }
        long others = context.getUser().getAttributeStream(INVITED_BY).filter(d -> !d.equals(client.getClientId())).count();
        context.challenge(context.form()
                .setAttribute("leaveName", nameOf(client))
                .setAttribute("leaveNothing", false)
                .setAttribute("leaveLast", others == 0)
                .setAttribute("leaveDays", DELETE_AFTER_SECONDS / 86400)
                .createForm("family-leave.ftl"));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        ClientModel client = domainOf(context);
        if (client == null || !form.containsKey("confirm") || !invited(context, client)) {
            LOG.infof("leave: cancelled for %s", client == null ? "a client that is not a domain's" : client.getClientId());
            context.cancel();
            return;
        }
        FamilyRemoval.leave(context.getSession(), context.getRealm(), context.getUser(), client, FamilyRemoval.Reason.LEFT);
        AuthenticationManager.expireIdentityCookie(context.getSession());
        // The session the app would get a code for is gone: back with the outcome only.
        String redirect = context.getAuthenticationSession().getRedirectUri();
        String state = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.STATE_PARAM);
        context.challenge(Response.seeOther(landing(redirect, state)).build());
    }

    /** The app's (already validated) redirect URI with its state and kc_action_status=success, no code. */
    static java.net.URI landing(String redirectUri, String state) {
        org.keycloak.common.util.KeycloakUriBuilder uri = org.keycloak.common.util.KeycloakUriBuilder.fromUri(redirectUri);
        if (state != null) {
            uri.queryParam(OIDCLoginProtocol.STATE_PARAM, state);
        }
        return uri.queryParam("kc_action", PROVIDER_ID).queryParam("kc_action_status", "success").build();
    }

    static String nameOf(ClientModel client) {
        String name = client.getAttribute(TENANT_NAME);
        return name == null || name.isBlank() ? client.getClientId() : name;
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "Leave a domain (remove my access)";
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
