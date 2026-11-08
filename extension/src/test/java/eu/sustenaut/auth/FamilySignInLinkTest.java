package eu.sustenaut.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/** The emailed link and code of the family sign-in (FamilySignInForm, FamilyLinkToken) and where an invitation lands. */
class FamilySignInLinkTest {

    /** An authentication session with only its notes and its root id. */
    static AuthenticationSessionModel session(String rootId, Map<String, String> notes) {
        RootAuthenticationSessionModel root = (RootAuthenticationSessionModel) Proxy.newProxyInstance(
                FamilySignInLinkTest.class.getClassLoader(), new Class<?>[] {RootAuthenticationSessionModel.class},
                (proxy, method, args) -> method.getName().equals("getId") ? rootId : null);
        return (AuthenticationSessionModel) Proxy.newProxyInstance(FamilySignInLinkTest.class.getClassLoader(),
                new Class<?>[] {AuthenticationSessionModel.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getParentSession" -> root;
                    case "getAuthNote" -> notes.get((String) args[0]);
                    case "setAuthNote" -> notes.put((String) args[0], (String) args[1]);
                    case "removeAuthNote" -> notes.remove((String) args[0]);
                    default -> null;
                });
    }

    static AuthenticationSessionModel asked(Map<String, String> notes, String rootId, String secret, long expires) {
        AuthenticationSessionModel auth = session(rootId, notes);
        notes.put(FamilySignInForm.NOTE_USER, "user-1");
        notes.put(FamilySignInForm.NOTE_EXPIRES, Long.toString(expires));
        notes.put(FamilySignInForm.NOTE_LINK_HASH, FamilySignInForm.hash(auth, "link", secret));
        return auth;
    }

    @Test
    void theCodeIsSixDigitsAndBelongsToItsLink() {
        Set<String> codes = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            String secret = FamilySignInForm.newLinkSecret();
            assertTrue(secret.matches("[A-Za-z0-9_-]{43}"), secret);
            String code = FamilySignInForm.codeFor(secret);
            assertTrue(code.matches("\\d{6}"), code);
            assertEquals(code, FamilySignInForm.codeFor(secret), "the same link always shows the same code");
            codes.add(code);
        }
        assertTrue(codes.size() > 190, "codes differ from link to link");
    }

    @Test
    void theLinkWorksOnlyInItsSessionWhileCurrent() {
        String secret = FamilySignInForm.newLinkSecret();
        long later = Instant.now().getEpochSecond() + 600;
        Map<String, String> notes = new HashMap<>();
        AuthenticationSessionModel auth = asked(notes, "root-1", secret, later);
        assertEquals("user-1", FamilySignInForm.linkUser(auth, secret));
        assertNull(FamilySignInForm.linkUser(auth, FamilySignInForm.newLinkSecret()), "another secret");
        assertNull(FamilySignInForm.linkUser(session("root-2", new HashMap<>(notes)), secret),
                "the same notes in another session (the hash is salted with the session)");
        assertNull(FamilySignInForm.linkUser(asked(new HashMap<>(), "root-1", secret, later - 601), secret), "expired");

        FamilySignInForm.clearCode(auth); // the code was used, or the link
        assertNull(FamilySignInForm.linkUser(auth, secret), "used once, gone");
        assertTrue(notes.isEmpty(), notes.toString());
    }

    @Test
    void anUnknownAddressHasNoLinkThatMatches() {
        String secret = FamilySignInForm.newLinkSecret();
        Map<String, String> notes = new HashMap<>();
        AuthenticationSessionModel auth = asked(notes, "root-1", secret, Instant.now().getEpochSecond() + 600);
        notes.put(FamilySignInForm.NOTE_LINK_HASH, "none");
        assertNull(FamilySignInForm.linkUser(auth, secret));
        assertNotEquals("none", FamilySignInForm.hash(auth, "link", ""));
    }

    @Test
    void theTokenCarriesTheSecretAndTheSession() throws Exception {
        FamilyLinkToken token = new FamilyLinkToken("user-1", 1_900_000_000, UUID.randomUUID(), "asid.tab.client",
                "example.net", "s3cret");
        FamilyLinkToken back = JsonSerialization.readValue(JsonSerialization.writeValueAsString(token), FamilyLinkToken.class);
        assertEquals("s3cret", back.getSecret());
        assertEquals("asid.tab.client", back.getCompoundAuthenticationSessionId());
        assertEquals("example.net", back.getIssuedFor());
        assertEquals(FamilyLinkToken.TOKEN_TYPE, back.getActionId());
        assertEquals("user-1", back.getUserId());
    }

    static ClientModel client(Map<String, String> attributes, String baseUrl) {
        return (ClientModel) Proxy.newProxyInstance(FamilySignInLinkTest.class.getClassLoader(),
                new Class<?>[] {ClientModel.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getAttribute" -> attributes.get((String) args[0]);
                    case "getBaseUrl" -> baseUrl;
                    default -> null;
                });
    }

    @Test
    void anInvitationLandsOnTheDomainsHomePage() {
        Map<String, String> active = new HashMap<>(Map.of(AppRegistration.STATE, "active"));
        assertEquals("https://share.example.net/", FamilyInviteSignIn.home(client(active, "https://share.example.net/")));
        active.put(AppRegistration.TENANT_HOME, "https://photos.example.net/");
        assertEquals("https://photos.example.net/", FamilyInviteSignIn.home(client(active, "https://share.example.net/")),
                "the domain's own setting first");
        assertNull(FamilyInviteSignIn.home(client(Map.of(), "/realms/family/account/")), "not a registered domain");
        assertNull(FamilyInviteSignIn.home(client(Map.of(AppRegistration.STATE, "active"), "http://x.example.net/")),
                "https only");
        assertNull(FamilyInviteSignIn.home(null));
    }
}
