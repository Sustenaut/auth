package eu.sustenaut.auth;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.WebAuthnPasswordlessRegisterFactory;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.grants.device.DeviceGrantType;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * After a sign-in by email (link, code or invitation), on a device that has not been asked:
 * "Skip the email next time on this device?". Asked per device, whether or not the person has a
 * passkey elsewhere; never after a passkey sign-in, in the device flow (app registration), when
 * an app asked for an action itself (kc_action, e.g. adding a passkey), or while an invitation
 * link is being opened (the domain's own sign-in right after it asks).
 *
 * <p>"Set up" runs Keycloak's passkey registration (webauthn-register-passwordless) inside this
 * action, so its page and its error page get a "Not now" too ({@code familySkip}; theme family):
 * a failed WebAuthn never traps anyone. "Not now", here or there, goes on to the app. Any answer
 * is kept on the device with a long-lived cookie on the realm's path ({@value #COOKIE}).
 */
public class FamilyPasskeyOffer implements RequiredActionProvider, RequiredActionFactory {

    public static final String PROVIDER_ID = "family-passkey-offer";
    static final String COOKIE = "FAMILY_PASSKEY_ASKED";
    /** About 400 days, the longest a browser keeps a cookie. */
    static final int COOKIE_SECONDS = 400 * 24 * 3600;
    /** User session note: how this session signed in, "email" or "passkey" (FamilySignInForm, FamilyInviteSignIn). */
    static final String SIGNED_IN_BY = "family.signed-in-by";
    private static final String NOTE_OFFERED = "family.passkey-offered";
    private static final String NOTE_SETUP = "family.passkey-setup";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        if (context.getUser() == null || auth.getAuthNote(NOTE_OFFERED) != null
                || auth.getAuthNote(AuthenticationManager.END_AFTER_REQUIRED_ACTIONS) != null
                || DeviceGrantType.isOAuth2DeviceVerificationFlow(auth)
                || auth.getClientNote(Constants.KC_ACTION) != null
                || auth.getClientNote(Constants.KC_ACTION_STATUS) != null // the app's action, done
                || asked(context) || !"email".equals(signedInBy(context))) {
            return;
        }
        auth.setAuthNote(NOTE_OFFERED, "true");
        auth.addRequiredAction(PROVIDER_ID);
    }

    /** How the session signed in: this sign-in's note, or for a session cookie, that session's. */
    private static String signedInBy(RequiredActionContext context) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        String by = auth.getUserSessionNotes().get(SIGNED_IN_BY);
        if (by == null && auth.getAuthNote(AuthenticationManager.SSO_AUTH) != null) {
            AuthenticationManager.AuthResult cookie =
                    AuthenticationManager.authenticateIdentityCookie(context.getSession(), context.getRealm(), true);
            UserSessionModel session = cookie == null ? null : cookie.session();
            by = session == null ? null : session.getNote(SIGNED_IN_BY);
        }
        return by;
    }

    private static boolean asked(RequiredActionContext context) {
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get(COOKIE);
        return cookie != null && !cookie.getValue().isEmpty();
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        if (context.getAuthenticationSession().getAuthNote(NOTE_SETUP) != null) {
            registration(context).requiredActionChallenge(withSkip(context));
        } else {
            context.challenge(context.form().createForm("family-passkey-offer.ftl"));
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        if (form.containsKey("notnow")) {
            remember(context);
            auth.removeAuthNote(NOTE_SETUP);
            context.success();
        } else if (auth.getAuthNote(NOTE_SETUP) != null) {
            registration(context).processAction(withSkip(context)); // success, or its page again
        } else if (form.containsKey("setup")) {
            remember(context);
            auth.setAuthNote(NOTE_SETUP, "true");
            registration(context).requiredActionChallenge(withSkip(context));
        } else {
            requiredActionChallenge(context);
        }
    }

    private static RequiredActionProvider registration(RequiredActionContext context) {
        KeycloakSession session = context.getSession();
        RequiredActionFactory factory = (RequiredActionFactory) session.getKeycloakSessionFactory()
                .getProviderFactory(RequiredActionProvider.class, WebAuthnPasswordlessRegisterFactory.PROVIDER_ID);
        return factory.create(session);
    }

    /** The context, with every page it makes marked familySkip (its forms post back to this action). */
    private static RequiredActionContext withSkip(RequiredActionContext context) {
        return (RequiredActionContext) Proxy.newProxyInstance(FamilyPasskeyOffer.class.getClassLoader(),
                new Class<?>[] {RequiredActionContext.class}, (proxy, method, args) -> {
                    try {
                        Object result = method.invoke(context, args);
                        return method.getName().equals("form") && result instanceof LoginFormsProvider forms
                                ? forms.setAttribute("familySkip", true)
                                : result;
                    } catch (InvocationTargetException e) {
                        throw e.getCause();
                    }
                });
    }

    private static void remember(RequiredActionContext context) {
        var uri = context.getUriInfo();
        String path = RealmsResource.realmBaseUrl(uri).build(context.getRealm().getName()).getRawPath();
        context.getSession().getContext().getHttpResponse().setCookieIfAbsent(new NewCookie.Builder(COOKIE)
                .value("1")
                .path(path)
                .maxAge(COOKIE_SECONDS)
                .secure("https".equals(uri.getBaseUri().getScheme()))
                .httpOnly(true)
                .sameSite(NewCookie.SameSite.LAX)
                .build());
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
        return "Family: offer a passkey on this device after an emailed sign-in";
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
