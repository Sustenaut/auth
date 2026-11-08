package eu.sustenaut.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

/**
 * The first-sign-in notice's body and signature (SignInNotice), against values computed
 * independently (Python's hmac), so a receiver in any language can check them the same way.
 */
class SignInNoticeTest {

    static final String BODY =
            "{\"event\":\"first_sign_in\",\"domain\":\"example.net\",\"email\":\"anna@example.org\",\"at\":\"2026-10-28T12:00:00Z\"}";

    @Test
    void body() {
        assertEquals(BODY, SignInNotice.body("example.net", "anna@example.org", 1793188800L));
    }

    @Test
    void signatureOverTimestampAndBody() {
        assertEquals("sha256=403d6143d258f71fc120736a45d7af28ecddcafe96dd9702c746a44c4381eec6",
                SignInNotice.sign("s3cret", 1793180000L, BODY));
    }

    @Test
    void anotherTimestampOrSecretSignsDifferently() {
        String good = SignInNotice.sign("s3cret", 1793180000L, BODY);
        assertNotEquals(good, SignInNotice.sign("s3cret", 1793180001L, BODY));
        assertNotEquals(good, SignInNotice.sign("other", 1793180000L, BODY));
        assertNotEquals(good, SignInNotice.sign("s3cret", 1793180000L, BODY + " "));
    }
}
