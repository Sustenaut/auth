package eu.sustenaut.auth;

import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.actiontoken.AbstractActionTokenHandler;
import org.keycloak.authentication.actiontoken.ActionTokenContext;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Opens the "Sign me in" link ({@link FamilyLinkToken}). Keycloak hands over the browser's
 * authentication session when its cookie and the link's tab match (the browser that asked),
 * else a fresh one.
 *
 * <ul>
 *   <li>The browser that asked, with the link's secret current: the code and link end, and the
 *       sign-in finishes (the browser flow again; {@link FamilySignInForm#authenticate} takes the
 *       note left here).
 *   <li>Any other browser or device: the code, in large digits, to type where the person started.
 *       Nothing signs in there and nothing is used up; the fresh session is dropped.
 *   <li>A link that is used, replaced (a new code was sent), expired or tried too often: a page
 *       saying so.
 * </ul>
 */
public class FamilyLinkHandler extends AbstractActionTokenHandler<FamilyLinkToken> {

    public FamilyLinkHandler() {
        super(FamilyLinkToken.TOKEN_TYPE, FamilyLinkToken.class, "familyLinkUsed", EventType.EXECUTE_ACTION_TOKEN,
                Errors.EXPIRED_CODE);
    }

    @Override
    public Response handleToken(FamilyLinkToken token, ActionTokenContext<FamilyLinkToken> context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        AuthenticationSessionModel current = context.getAuthenticationSession();
        if (!context.isAuthenticationSessionFresh()) {
            if (token.getUserId().equals(FamilySignInForm.linkUser(current, token.getSecret()))) {
                FamilySignInForm.clearCode(current);
                current.setAuthNote(FamilySignInForm.NOTE_LINK_USER, token.getUserId());
                context.getEvent().detail("family_sign_in", "link");
                return context.processFlow(false, LoginActionsService.AUTHENTICATE_PATH,
                        AuthenticationFlowResolver.resolveBrowserFlow(current), null, new AuthenticationProcessor());
            }
            return page(session, null);
        }
        AuthenticationSessionModel asked = askedIn(session, realm, token);
        String code = asked != null && token.getUserId().equals(FamilySignInForm.linkUser(asked, token.getSecret()))
                ? FamilySignInForm.codeFor(token.getSecret())
                : null;
        new AuthenticationSessionManager(session).removeAuthenticationSession(realm, current, true);
        context.getEvent().detail("family_sign_in", code == null ? "link_unusable" : "link_elsewhere");
        return page(session, code);
    }

    /** The authentication session the link was made for, if it still exists. */
    private static AuthenticationSessionModel askedIn(KeycloakSession session, RealmModel realm, FamilyLinkToken token) {
        String compound = token.getCompoundAuthenticationSessionId();
        if (compound == null) {
            return null;
        }
        AuthenticationSessionCompoundId id = AuthenticationSessionCompoundId.encoded(compound);
        RootAuthenticationSessionModel root = session.authenticationSessions().getRootAuthenticationSession(realm, id.getRootSessionId());
        ClientModel client = realm.getClientById(id.getClientUUID());
        return root == null || client == null ? null : root.getAuthenticationSession(client, id.getTabId());
    }

    /** The code to type on the first screen, or (code null) "this link no longer works". */
    private static Response page(KeycloakSession session, String code) {
        LoginFormsProvider forms = session.getProvider(LoginFormsProvider.class).setDetachedAuthSession();
        if (code != null) {
            forms.setAttribute("familyLinkCode", code);
        }
        return forms.createForm("login-family-link.ftl");
    }
}
