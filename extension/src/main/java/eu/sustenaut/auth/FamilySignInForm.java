package eu.sustenaut.auth;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.WebAuthnConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.email.EmailException;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionCompoundId;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The sign-in page of the invite-only realms, family and team (each with its own theme): one
 * email field (a passkey, if the person has one, is offered in it by the browser: Keycloak's
 * conditional UI), and otherwise one email with a six-digit code and a "Sign me in" link. There
 * is no password step: the parent's username/password path is never used.
 *
 * <p>Invite only. An address with no account gets the same "we sent you an email" page as a
 * known one, but no email and nothing that could match, so the page neither tells who has
 * an account nor creates one. Code and link are good for {@link #CODE_TTL_SECONDS} (the realm
 * attribute {@value #TTL_ATTRIBUTE} overrides it, for the proofs), in this browser's sign-in
 * only: both live in the authentication session, as hashes. The code allows
 * {@link #MAX_ATTEMPTS} tries. Using either one ends both.
 *
 * <p>The link is an action token ({@link FamilyLinkHandler}) carrying a random secret; the code
 * is derived from that secret, so the link can show the code without the code being stored.
 * Opened in the browser that asked, the link signs in ({@link #authenticate} finishes on the
 * note the handler leaves); opened anywhere else it only shows the code.
 *
 * <p>The name is from the family realm, its first user. A later "link my wallet" step for
 * these realms would be a required action after this one signs someone in, never a way to
 * create an account (README, "Not in this first version").
 */
public class FamilySignInForm extends UsernamePasswordForm {

    private static final Logger LOG = Logger.getLogger(FamilySignInForm.class);

    static final long CODE_TTL_SECONDS = 600;
    static final String TTL_ATTRIBUTE = "sustenaut.family.codeSeconds";
    static final int MAX_ATTEMPTS = 5;
    static final long RESEND_AFTER_SECONDS = 30;
    /**
     * Per address, across sign-in attempts (a new attempt starts its own 5 tries): code emails,
     * at most 10 an hour and 50 a day; wrong codes, at most 10 an hour and 30 a day, after which
     * no code is taken for that address until the window moves on (the link and passkeys still
     * work). Six digits at 30 guesses a day: about one chance in 90 a year. The local stack
     * raises them (SUSTENAUT_CODE_EMAILS_PER_HOUR and _PER_DAY, SUSTENAUT_WRONG_CODES_PER_HOUR
     * and _PER_DAY), since its proofs sign the same people in many times.
     */
    static final AddressBudget EMAILS = new AddressBudget(
            limit("SUSTENAUT_CODE_EMAILS_PER_HOUR", 10), limit("SUSTENAUT_CODE_EMAILS_PER_DAY", 50));
    static final AddressBudget WRONG_CODES = new AddressBudget(
            limit("SUSTENAUT_WRONG_CODES_PER_HOUR", 10), limit("SUSTENAUT_WRONG_CODES_PER_DAY", 30));

    private static int limit(String variable, int otherwise) {
        try {
            return Integer.parseInt(System.getenv().getOrDefault(variable, Integer.toString(otherwise)).trim());
        } catch (NumberFormatException e) {
            return otherwise;
        }
    }

    private static final String NOTE_EMAIL = "family.email";
    static final String NOTE_USER = "family.user";
    private static final String NOTE_HASH = "family.code-hash";
    static final String NOTE_LINK_HASH = "family.link-hash";
    static final String NOTE_EXPIRES = "family.code-expires";
    private static final String NOTE_SENT = "family.code-sent";
    private static final String NOTE_ATTEMPTS = "family.code-attempts";
    /** Left by {@link FamilyLinkHandler} when the link was opened in this browser: the user's id. */
    static final String NOTE_LINK_USER = "family.link-user";

    private static final SecureRandom RANDOM = new SecureRandom();

    public FamilySignInForm(KeycloakSession session) {
        super(session);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        String linked = auth.getAuthNote(NOTE_LINK_USER);
        if (linked != null) {
            auth.removeAuthNote(NOTE_LINK_USER);
            UserModel user = context.getSession().users().getUserById(context.getRealm(), linked);
            if (user != null && user.isEnabled()) {
                signedIn(auth, "email");
                context.setUser(user);
                context.success();
                return;
            }
        }
        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        if (form.containsKey("cancel")) {
            context.cancelLogin();
        } else if (webauthnAuth.isPasskeysEnabled()
                && (form.containsKey(WebAuthnConstants.AUTHENTICATOR_DATA) || form.containsKey(WebAuthnConstants.ERROR))) {
            signedIn(context.getAuthenticationSession(), "passkey");
            webauthnAuth.action(context); // a passkey: Keycloak's own check, then success
        } else if (form.containsKey("restart")) {
            clearCode(context.getAuthenticationSession());
            authenticate(context);
        } else if (form.containsKey("resend")) {
            String email = context.getAuthenticationSession().getAuthNote(NOTE_EMAIL);
            if (email == null) {
                authenticate(context);
            } else {
                sendCode(context, email, true);
            }
        } else if (form.containsKey("code")) {
            checkCode(context, form.getFirst("code"));
        } else {
            String email = context.getUser() != null ? context.getUser().getEmail() : form.getFirst("username");
            if (email == null || email.isBlank()) {
                context.challenge(challenge(context, "familyEmailMissing", "username"));
            } else {
                sendCode(context, email.trim(), false);
            }
        }
    }

    /**
     * Sign-ins are remembered (remember-me lifetimes, also across browser restarts) where the realm
     * allows it (family; Keycloak drops a remember-me session in a realm without it, e.g. team);
     * the session notes how ("email" or "passkey"), for {@link FamilyPasskeyOffer}.
     */
    static void signedIn(AuthenticationSessionModel auth, String how) {
        if (auth.getRealm().isRememberMe()) {
            auth.setAuthNote(Details.REMEMBER_ME, "true");
        }
        auth.setUserSessionNote(FamilyPasskeyOffer.SIGNED_IN_BY, how);
    }

    static long ttlSeconds(RealmModel realm) {
        String value = realm.getAttribute(TTL_ATTRIBUTE);
        try {
            return value == null || value.isBlank() ? CODE_TTL_SECONDS : Math.max(1, Long.parseLong(value.trim()));
        } catch (NumberFormatException e) {
            return CODE_TTL_SECONDS;
        }
    }

    private void sendCode(AuthenticationFlowContext context, String email, boolean resend) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        long now = Instant.now().getEpochSecond();
        long ttl = ttlSeconds(context.getRealm());
        String sent = auth.getAuthNote(NOTE_SENT);
        if (resend && sent != null && now - Long.parseLong(sent) < RESEND_AFTER_SECONDS) {
            context.challenge(codePage(context, email).setError("familyCodeWait").createForm("login-family-code.ftl"));
            return;
        }
        long nowMs = System.currentTimeMillis();
        if (!EMAILS.allows(email, nowMs)) {
            // Known address or not, the same page: the limit says nothing about who has an account.
            clearCode(auth);
            auth.setAuthNote(NOTE_EMAIL, email);
            context.getEvent().detail("family_email_code", "address_limit");
            LOG.info("family sign-in: too many code emails for one address; none sent");
            context.challenge(codePage(context, email).setError("familyCodeLimit").createForm("login-family-code.ftl"));
            return;
        }
        EMAILS.spend(email, nowMs);
        clearCode(auth);
        auth.setAuthNote(NOTE_EMAIL, email);
        auth.setAuthNote(NOTE_SENT, Long.toString(now));
        auth.setAuthNote(NOTE_EXPIRES, Long.toString(now + ttl));
        auth.setAuthNote(NOTE_ATTEMPTS, "0");

        UserModel user = context.getUser() != null
                ? context.getUser()
                : KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), email);
        if (user == null || !user.isEnabled() || user.getEmail() == null) {
            // Unknown address: same page, nothing sent, hashes nothing can match.
            auth.setAuthNote(NOTE_HASH, "none");
            auth.setAuthNote(NOTE_LINK_HASH, "none");
            context.getEvent().detail("family_email_code", "unknown_address");
            LOG.debugf("family sign-in: no account for the address given; no code sent");
        } else {
            String secret = newLinkSecret();
            String code = codeFor(secret);
            auth.setAuthNote(NOTE_USER, user.getId());
            auth.setAuthNote(NOTE_HASH, hash(auth, "code", code));
            auth.setAuthNote(NOTE_LINK_HASH, hash(auth, "link", secret));
            try {
                // In the words of the domain the person is signing in to (its settings), if any.
                TenantEmail mail = new TenantEmail(context.getSession(), auth.getClient());
                mail.setUser(user);
                mail.setAuthenticationSession(auth);
                String tenant = mail.tenantName();
                mail.sendTenant(tenant == null ? "familyCodeSubject" : "familyCodeSubjectFor",
                        tenant == null ? java.util.List.of() : java.util.List.of(tenant), "family-code.ftl",
                        new HashMap<>(Map.of("code", code, "minutes", Math.max(1, (ttl + 59) / 60),
                                "link", link(context, auth, user, secret, now + ttl))));
            } catch (EmailException e) {
                LOG.warn("family sign-in: could not send the code email", e);
                clearCode(auth);
                context.challenge(challenge(context, "familyCodeNotSent", "username"));
                return;
            }
        }
        context.challenge(codePage(context, email).createForm("login-family-code.ftl"));
    }

    /** The "Sign me in" link: an action token tied to this authentication session (its tab). */
    private static String link(AuthenticationFlowContext context, AuthenticationSessionModel auth, UserModel user,
            String secret, long expires) {
        FamilyLinkToken token = new FamilyLinkToken(user.getId(), (int) expires, UUID.randomUUID(),
                AuthenticationSessionCompoundId.fromAuthSession(auth).getEncodedId(), auth.getClient().getClientId(), secret);
        var uri = context.getUriInfo();
        return Urls.actionTokenBuilder(uri.getBaseUri(), token.serialize(context.getSession(), context.getRealm(), uri),
                        auth.getClient().getClientId(), auth.getTabId(),
                        AuthenticationProcessor.getClientData(context.getSession(), auth))
                .build(context.getRealm().getName()).toString();
    }

    private void checkCode(AuthenticationFlowContext context, String given) {
        AuthenticationSessionModel auth = context.getAuthenticationSession();
        String email = auth.getAuthNote(NOTE_EMAIL);
        String expected = auth.getAuthNote(NOTE_HASH);
        if (email == null || expected == null) {
            authenticate(context);
            return;
        }
        int attempts = Integer.parseInt(auth.getAuthNote(NOTE_ATTEMPTS)) + 1;
        auth.setAuthNote(NOTE_ATTEMPTS, Integer.toString(attempts));
        boolean expired = Instant.now().getEpochSecond() > Long.parseLong(auth.getAuthNote(NOTE_EXPIRES));
        if (!expired && !WRONG_CODES.allows(email, System.currentTimeMillis())) {
            // Too many wrong codes for this address lately: no code is taken, right or not. The
            // emailed link still works.
            context.getEvent().detail("family_email_code", "address_limit");
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                    codePage(context, email).setError("familyCodeLimit").createForm("login-family-code.ftl"));
            return;
        }
        if (expired || attempts > MAX_ATTEMPTS) {
            auth.setAuthNote(NOTE_HASH, "none");
            auth.setAuthNote(NOTE_LINK_HASH, "none");
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                    codePage(context, email).setError("familyCodeExpired").createForm("login-family-code.ftl"));
            return;
        }
        String code = given == null ? "" : given.replaceAll("\\s", "");
        String userId = auth.getAuthNote(NOTE_USER);
        UserModel user = userId == null ? null : context.getSession().users().getUserById(context.getRealm(), userId);
        if (!matches(expected, hash(auth, "code", code)) || user == null || !user.isEnabled()) {
            WRONG_CODES.spend(email, System.currentTimeMillis());
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    codePage(context, email).setError("familyCodeWrong").createForm("login-family-code.ftl"));
            return;
        }
        clearCode(auth); // the link dies with it
        signedIn(auth, "email");
        context.setUser(user);
        context.success();
    }

    /**
     * The link's check, in the authentication session it was made for: the user's id if the
     * secret is the current one and not expired, else null. Changes nothing.
     */
    static String linkUser(AuthenticationSessionModel auth, String secret) {
        String expected = auth.getAuthNote(NOTE_LINK_HASH);
        String expires = auth.getAuthNote(NOTE_EXPIRES);
        if (expected == null || expires == null || secret == null
                || Instant.now().getEpochSecond() > Long.parseLong(expires)) {
            return null;
        }
        return matches(expected, hash(auth, "link", secret)) ? auth.getAuthNote(NOTE_USER) : null;
    }

    private LoginFormsProvider codePage(AuthenticationFlowContext context, String email) {
        return context.form().setAttribute("familyEmail", email);
    }

    static void clearCode(AuthenticationSessionModel auth) {
        for (String note : new String[] {NOTE_EMAIL, NOTE_USER, NOTE_HASH, NOTE_LINK_HASH, NOTE_EXPIRES, NOTE_SENT,
                NOTE_ATTEMPTS}) {
            auth.removeAuthNote(note);
        }
    }

    /** 32 random bytes, URL-safe: a link's secret. */
    static String newLinkSecret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** The six-digit code that goes with a link secret. */
    static String codeFor(String secret) {
        long n = ByteBuffer.wrap(sha256("family-code", "", secret)).getLong();
        return String.format("%06d", Long.remainderUnsigned(n, 1_000_000));
    }

    /** Hash of a code or link secret, salted with this authentication session's id. */
    static String hash(AuthenticationSessionModel auth, String kind, String value) {
        return HexFormat.of().formatHex(sha256(kind, auth.getParentSession().getId(), value));
    }

    private static byte[] sha256(String label, String salt, String value) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(label.getBytes(StandardCharsets.UTF_8));
            sha.update((byte) 0);
            sha.update(salt.getBytes(StandardCharsets.UTF_8));
            sha.update((byte) 0);
            return sha.digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static boolean matches(String expected, String actual) {
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII), actual.getBytes(StandardCharsets.US_ASCII));
    }

    // The page is the username form (theme family: login-username.ftl), never username+password.

    @Override
    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();
        if (!formData.isEmpty()) forms.setFormData(formData);
        return forms.createLoginUsername();
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginUsername();
    }

    @Override
    protected String getDefaultChallengeMessage(AuthenticationFlowContext context) {
        return "familyEmailMissing";
    }
}
