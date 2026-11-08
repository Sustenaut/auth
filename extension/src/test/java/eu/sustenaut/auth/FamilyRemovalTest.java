package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.sustenaut.auth.FamilyRemoval.Outcome;
import eu.sustenaut.auth.FamilyRemoval.Reason;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.UserSessionProvider;

/**
 * FamilyRemoval.leave on stand-in models (dynamic proxies, no Keycloak running): which mark goes,
 * when the account is switched off and stamped, that every session ends, and that an account
 * an admin locked stays as it was. The email is not sent here (no theme): leave goes on without it.
 */
class FamilyRemovalTest {

    /** A stand-in user: attributes, enabled, email; nothing else. */
    static final class FakeUser {
        final Map<String, List<String>> attributes = new LinkedHashMap<>();
        boolean enabled = true;
        String email = "anna@example.org";

        UserModel model() {
            return (UserModel) Proxy.newProxyInstance(UserModel.class.getClassLoader(), new Class<?>[] {UserModel.class},
                    (proxy, method, args) -> switch (method.getName()) {
                        case "getId" -> "user-1";
                        case "getEmail" -> email;
                        case "isEnabled" -> enabled;
                        case "setEnabled" -> { enabled = (Boolean) args[0]; yield null; }
                        case "getAttributeStream" -> attributes.getOrDefault(args[0], List.of()).stream();
                        case "getFirstAttribute" -> attributes.getOrDefault(args[0], List.of()).stream().findFirst().orElse(null);
                        case "setAttribute" -> { attributes.put((String) args[0], new ArrayList<>((List<String>) args[1])); yield null; }
                        case "setSingleAttribute" -> { attributes.put((String) args[0], List.of((String) args[1])); yield null; }
                        case "removeAttribute" -> { attributes.remove(args[0]); yield null; }
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == args[0];
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
        }
    }

    /** A session whose user has two sessions and one offline session; records what ends them. */
    static final class FakeSession {
        final List<String> removed = new ArrayList<>();
        Integer notBefore;

        KeycloakSession model() {
            UserSessionModel online1 = userSession("s1"), online2 = userSession("s2"), offline = userSession("o1");
            UserSessionProvider sessions = proxy(UserSessionProvider.class, (method, args) -> switch (method) {
                case "getUserSessionsStream" -> Stream.of(online1, online2);
                case "getOfflineUserSessionsStream" -> Stream.of(offline);
                case "removeUserSession" -> { removed.add(((UserSessionModel) args[1]).getId()); yield null; }
                case "removeOfflineUserSession" -> { removed.add("offline:" + ((UserSessionModel) args[1]).getId()); yield null; }
                default -> throw new UnsupportedOperationException(method);
            });
            UserProvider users = proxy(UserProvider.class, (method, args) -> switch (method) {
                case "setNotBeforeForUser" -> { notBefore = (Integer) args[2]; yield null; }
                default -> throw new UnsupportedOperationException(method);
            });
            KeycloakContext context = proxy(KeycloakContext.class, (method, args) -> null);
            return proxy(KeycloakSession.class, (method, args) -> switch (method) {
                case "sessions" -> sessions;
                case "users" -> users;
                case "getContext" -> context;
                default -> null; // providers: none (the email fails and is logged)
            });
        }

        static UserSessionModel userSession(String id) {
            return proxy(UserSessionModel.class, (method, args) -> "getId".equals(method) ? id : null);
        }
    }

    interface Handler {
        Object handle(String method, Object[] args);
    }

    @SuppressWarnings("unchecked")
    static <T> T proxy(Class<T> type, Handler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
                (p, method, args) -> switch (method.getName()) {
                    case "hashCode" -> System.identityHashCode(p);
                    case "equals" -> p == args[0];
                    case "toString" -> type.getSimpleName();
                    default -> handler.handle(method.getName(), args);
                });
    }

    static ClientModel domainClient(String domain) {
        Map<String, String> attributes = new HashMap<>(Map.of(DOMAIN, domain, TENANT_NAME, "The Examples"));
        return proxy(ClientModel.class, (method, args) -> switch (method) {
            case "getAttribute" -> attributes.get(args[0]);
            case "getClientId" -> domain;
            default -> null;
        });
    }

    static final RealmModel REALM = proxy(RealmModel.class, (method, args) -> null);

    @Test
    void theLastDomainSwitchesTheAccountOffAndStampsIt() {
        FakeUser anna = new FakeUser();
        anna.attributes.put(INVITED_BY, List.of("example.net"));
        FakeSession session = new FakeSession();
        long before = Time.currentTime();
        Outcome outcome = FamilyRemoval.leave(session.model(), REALM, anna.model(), domainClient("example.net"), Reason.REMOVED);
        assertEquals(Outcome.DISABLED, outcome);
        assertFalse(anna.enabled);
        assertNull(anna.attributes.get(INVITED_BY), "no marks left");
        long stamped = Long.parseLong(anna.attributes.get(REMOVED_AT).get(0));
        assertTrue(stamped >= before && stamped <= Time.currentTime() + 1);
        assertEquals(List.of("s1", "s2", "offline:o1"), session.removed, "every session ends, offline ones too");
        assertTrue(session.notBefore != null && session.notBefore >= before, "tokens issued before now stop working");
    }

    @Test
    void anotherDomainKeepsTheAccount() {
        FakeUser anna = new FakeUser();
        anna.attributes.put(INVITED_BY, List.of("sustenaut.eu", "example.net"));
        FakeSession session = new FakeSession();
        Outcome outcome = FamilyRemoval.leave(session.model(), REALM, anna.model(), domainClient("example.net"), Reason.LEFT);
        assertEquals(Outcome.KEPT, outcome);
        assertTrue(anna.enabled);
        assertEquals(List.of("sustenaut.eu"), anna.attributes.get(INVITED_BY));
        assertNull(anna.attributes.get(REMOVED_AT));
        assertEquals(3, session.removed.size(), "sessions end all the same");
    }

    @Test
    void someoneTheDomainDidNotInviteIsNotTouched() {
        FakeUser anna = new FakeUser();
        anna.attributes.put(INVITED_BY, List.of("sustenaut.eu"));
        FakeSession session = new FakeSession();
        Outcome outcome = FamilyRemoval.leave(session.model(), REALM, anna.model(), domainClient("example.net"), Reason.REMOVED);
        assertEquals(Outcome.NOT_MARKED, outcome);
        assertTrue(anna.enabled);
        assertEquals(List.of("sustenaut.eu"), anna.attributes.get(INVITED_BY));
        assertEquals(List.of(), session.removed, "no session ends");
        assertNull(session.notBefore);

        FakeUser nobody = new FakeUser();
        assertEquals(Outcome.NOT_MARKED, FamilyRemoval.leave(
                session.model(), REALM, nobody.model(), domainClient("example.net"), Reason.REMOVED));
        assertTrue(nobody.attributes.isEmpty());
    }

    @Test
    void anAccountAnAdminLockedStaysLockedAndUnstamped() {
        FakeUser anna = new FakeUser();
        anna.enabled = false;
        anna.attributes.put(INVITED_BY, List.of("example.net"));
        Outcome outcome = FamilyRemoval.leave(new FakeSession().model(), REALM, anna.model(), domainClient("example.net"), Reason.REMOVED);
        assertEquals(Outcome.KEPT, outcome);
        assertFalse(anna.enabled);
        assertNull(anna.attributes.get(REMOVED_AT), "never stamped, so never deleted by the daily job");
        assertNull(anna.attributes.get(INVITED_BY));
    }

    @Test
    void marksComeOffOneDomainOnly() {
        assertEquals(List.of("a.eu", "c.eu"), FamilyRemoval.without(List.of("a.eu", "b.eu", "c.eu"), "b.eu"));
        assertEquals(List.of(), FamilyRemoval.without(List.of("b.eu", "b.eu"), "b.eu"), "duplicates too");
        assertNull(FamilyRemoval.without(List.of("a.eu"), "b.eu"));
        assertNull(FamilyRemoval.without(List.of(), "b.eu"));
        assertNull(FamilyRemoval.without(List.of("a.eu"), null));
    }

    @Test
    void deletionIsDueThirtyDaysAfterRemoval() {
        long now = 1_800_000_000L;
        long day = 24 * 3600;
        assertTrue(FamilyRemoval.due(Long.toString(now - 30 * day), now));
        assertTrue(FamilyRemoval.due(Long.toString(now - 400 * day), now));
        assertFalse(FamilyRemoval.due(Long.toString(now - 30 * day + 1), now));
        assertFalse(FamilyRemoval.due(Long.toString(now), now));
        assertFalse(FamilyRemoval.due(null, now), "not stamped: locked by an admin, kept");
        assertFalse(FamilyRemoval.due("soon", now));
    }

    @Test
    void theApiTakesRemovedOrMoved() {
        assertEquals(Reason.REMOVED, Reason.fromApi(null));
        assertEquals(Reason.REMOVED, Reason.fromApi("removed"));
        assertEquals(Reason.MOVED, Reason.fromApi("moved"));
        assertNull(Reason.fromApi("left"), "self-service only");
        assertNull(Reason.fromApi("gone"), "the deletion job only");
        assertNull(Reason.fromApi(3));
    }

    @Test
    void theNoticeNamesItsMessageAndTheDeletion() {
        Map<String, Object> moved = FamilyRemoval.notice("example.net", "The Examples", Reason.MOVED, true);
        assertEquals("moved", moved.get("reason"));
        assertEquals("The Examples", moved.get("domainName"));
        assertEquals(true, moved.get("disabled"));
        assertEquals(30L, moved.get("deleteDays"));
        assertEquals(false, FamilyRemoval.notice("example.net", "example.net", Reason.GONE, false).get("disabled"));
    }

    /** Every reason has its words in the email theme (skipped where the theme is not next to the code, e.g. in the image build). */
    @Test
    void everyReasonHasItsMessage() throws Exception {
        java.nio.file.Path file = java.nio.file.Path.of("../themes/family/email/messages/messages_en.properties");
        org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.Files.exists(file), "theme not here");
        java.util.Properties messages = new java.util.Properties();
        try (var in = java.nio.file.Files.newBufferedReader(file)) {
            messages.load(in);
        }
        for (Reason reason : Reason.values()) {
            assertTrue(messages.containsKey("familyRemoved_" + reason.word()), reason.word());
        }
        assertTrue(messages.containsKey("familyRemovedSubject") && messages.containsKey("familyRemovedDeleted"));
    }
}
