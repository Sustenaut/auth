package eu.sustenaut.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;

/** Which events PasskeyNotice reacts to, the order of the inviting domains, and the device hint. */
class PasskeyNoticeTest {

    static Event event(EventType type, String credentialType) {
        Event e = new Event();
        e.setType(type);
        e.setUserId("u1");
        e.setDetails(Map.of("credential_type", credentialType));
        return e;
    }

    @Test
    void onlyAnAddedPasskeyCounts() {
        assertTrue(PasskeyNotice.passkeyAdded(event(EventType.UPDATE_CREDENTIAL, "webauthn-passwordless")));
        assertFalse(PasskeyNotice.passkeyAdded(event(EventType.UPDATE_CREDENTIAL, "webauthn")), "a second factor");
        assertFalse(PasskeyNotice.passkeyAdded(event(EventType.UPDATE_CREDENTIAL, "password")));
        assertFalse(PasskeyNotice.passkeyAdded(event(EventType.CUSTOM_REQUIRED_ACTION, "webauthn-passwordless")),
                "the required action's own (deprecated) event: not counted twice");
        Event failed = event(EventType.UPDATE_CREDENTIAL, "webauthn-passwordless");
        failed.setError("invalid_user_credentials");
        assertFalse(PasskeyNotice.passkeyAdded(failed));
        Event noDetails = event(EventType.UPDATE_CREDENTIAL, "x");
        noDetails.setDetails(null);
        assertFalse(PasskeyNotice.passkeyAdded(noDetails));
    }

    @Test
    void theDomainThePasskeyWasAddedThroughComesFirst() {
        assertEquals(List.of("b.eu", "a.eu"), PasskeyNotice.candidates(List.of("a.eu", "b.eu"), "b.eu"));
        assertEquals(List.of("a.eu", "b.eu"), PasskeyNotice.candidates(List.of("a.eu", "b.eu"), "share-portal"));
        assertEquals(List.of("a.eu"), PasskeyNotice.candidates(List.of("a.eu"), null));
        assertEquals(List.of(), PasskeyNotice.candidates(List.of(), "a.eu"), "not invited by it: not its words");
    }

    @Test
    void aRoughDeviceHint() {
        assertEquals("Chrome on Android", PasskeyNotice.device(
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36"));
        assertEquals("Safari on an iPhone", PasskeyNotice.device(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"));
        assertEquals("Edge on Windows", PasskeyNotice.device(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"));
        assertEquals("Firefox on a Mac", PasskeyNotice.device(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 15.5; rv:144.0) Gecko/20100101 Firefox/144.0"));
        assertEquals("Chrome on Linux", PasskeyNotice.device(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36"));
        assertEquals("a browser on Windows", PasskeyNotice.device("SomeApp/1.0 (Windows NT 10.0)"));
        assertEquals("an unknown device", PasskeyNotice.device("curl/8.5.0"));
        assertEquals("an unknown device", PasskeyNotice.device(null));
    }
}
