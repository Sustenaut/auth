package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.STATE;
import static eu.sustenaut.auth.AppRegistration.TENANT_HOME;

import jakarta.ws.rs.core.Response;
import java.net.URI;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.DefaultActionTokenKey;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The invitation's one action: opening its link signs the person in. The invitation is
 * Keycloak's execute-actions email with this action (AppRegistrationResource's invite,
 * invite-family.sh); Keycloak first asks "Sign in?" once (so a mail scanner that opens links
 * signs nobody in), then this marks the address verified, starts a remembered session (the SSO
 * cookie) and goes to the inviting domain's home page, whose own sign-in then passes straight
 * through. Without a domain (invite-family.sh without INVITE_CLIENT) it says "you are signed in".
 *
 * <p>Execute-actions links otherwise only change the account, so the session and the end of
 * the link (single use, as Keycloak does at the end of required actions) are made here.
 */
public class FamilyInviteSignIn implements RequiredActionProvider, RequiredActionFactory {

    public static final String PROVIDER_ID = "family-invite-sign-in";
    private static final long CLOCK_SKEW_SECONDS = 60;
    private static final String NOTE_DONE = "family.invite-signed-in";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {}

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        KeycloakSession session = context.getSession();
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        UserModel user = context.getUser();
        if (auth.getAuthNote(AuthenticationManager.END_AFTER_REQUIRED_ACTIONS) == null) {
            context.success(); // set on an account, met in an ordinary sign-in: that is signing in already
            return;
        }
        if (auth.getAuthNote(NOTE_DONE) != null || !useUpLink(session, auth)) {
            context.challenge(context.form().setError("expiredActionMessage").createErrorPage(Response.Status.BAD_REQUEST));
            return;
        }
        user.setEmailVerified(true);
        FamilySignInForm.signedIn(auth, "email");
        auth.removeRequiredAction(PROVIDER_ID);
        auth.setAuthNote(NOTE_DONE, "true");
        UserSessionModel userSession = AuthenticationProcessor
                .attachSession(auth, null, session, context.getRealm(), context.getConnection(), context.getEvent())
                .getClientSession().getUserSession();
        AuthenticationManager.createLoginCookie(session, context.getRealm(), user, userSession, context.getUriInfo(),
                context.getConnection());
        context.getEvent().clone().event(EventType.LOGIN).detail("family_sign_in", "invitation").session(userSession).success();

        String home = home(auth.getClient());
        context.challenge(home != null
                ? Response.seeOther(URI.create(home)).build()
                : context.form().setDetachedAuthSession().setAttribute("messageHeader", "familyInviteSignedInTitle")
                        .setSuccess("familyInviteSignedIn").createInfoPage());
    }

    /** The invitation link works once (Keycloak's revoked-token list, until it would have expired). */
    private static boolean useUpLink(KeycloakSession session, AuthenticationSessionModel auth) {
        String serialized = auth.getAuthNote(AuthenticationManager.INVALIDATE_ACTION_TOKEN);
        if (serialized == null) {
            return true; // not from a link (an admin set the action on the account): nothing to end
        }
        DefaultActionTokenKey key = DefaultActionTokenKey.from(serialized);
        if (key == null || Time.currentTime() > key.getExp()) {
            return false;
        }
        auth.removeAuthNote(AuthenticationManager.INVALIDATE_ACTION_TOKEN);
        return session.revokedTokens().put(serialized, key.getExp() - Time.currentTime() + CLOCK_SKEW_SECONDS);
    }

    /** Where the person lands: the registered domain's home page (its settings, else its registration). */
    static String home(ClientModel client) {
        if (client == null || client.getAttribute(STATE) == null) {
            return null;
        }
        String home = client.getAttribute(TENANT_HOME);
        if (home == null || home.isBlank()) {
            home = client.getBaseUrl();
        }
        return home != null && home.startsWith("https://") ? home : null;
    }

    @Override
    public void processAction(RequiredActionContext context) {
        requiredActionChallenge(context);
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
        return "Family: the invitation signs in";
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
