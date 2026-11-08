package eu.sustenaut.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import eu.sustenaut.auth.AppRegistration.Answer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

/**
 * The DNSSEC decision of app registration (AppRegistration.validated) on made-up answers; and,
 * with LIVE_DNS=1 (network), the validating resolver against real signed, unsigned and
 * deliberately broken domains, from the IANA root trust anchors:
 *
 *   LIVE_DNS=1 mvn test        (DNS_RESOLVER=host[:port], default 1.1.1.1)
 */
class AppRegistrationDnsTest {

    static final String TOKEN = "a".repeat(64);
    static final String HASH = AppRegistration.sha256(TOKEN);

    static Message answer(int rcode, boolean validated, org.xbill.DNS.Record... records) {
        Message m = new Message();
        m.getHeader().setRcode(rcode);
        if (validated) m.getHeader().setFlag(Flags.AD);
        for (org.xbill.DNS.Record r : records) m.addRecord(r, Section.ANSWER);
        return m;
    }

    static TXTRecord txt(String value) throws Exception {
        return new TXTRecord(Name.fromString("_sustenaut-auth.example.net."), DClass.IN, 300, value);
    }

    @Test
    void aSignedDomainsRecordMustValidate() throws Exception {
        assertEquals(Answer.PRESENT, AppRegistration.validated(answer(Rcode.NOERROR, true, txt("sa1=" + TOKEN)), HASH));
        assertEquals(Answer.PRESENT, AppRegistration.validated(
                answer(Rcode.NOERROR, true, txt("v=spf1 -all"), txt("sa1=" + TOKEN)), HASH), "one of several TXT values");
        assertEquals(Answer.ABSENT, AppRegistration.validated(answer(Rcode.NOERROR, true, txt("sa1=" + "b".repeat(64))), HASH));
        assertEquals(Answer.ABSENT, AppRegistration.validated(answer(Rcode.NOERROR, true), HASH), "validated no-data");
        assertEquals(Answer.ABSENT, AppRegistration.validated(answer(Rcode.NXDOMAIN, true), HASH), "validated no such name");
        assertEquals(Answer.UNKNOWN, AppRegistration.validated(answer(Rcode.NOERROR, false, txt("sa1=" + TOKEN)), HASH),
                "the right value, but not validated");
        assertEquals(Answer.UNKNOWN, AppRegistration.validated(answer(Rcode.NXDOMAIN, false), HASH), "an unvalidated no");
        assertEquals(Answer.UNKNOWN, AppRegistration.validated(answer(Rcode.SERVFAIL, false), HASH), "bogus");
    }

    @Test
    void hostsMustBePlainHttpsUnderTheDomain() {
        assertEquals("share.example.net", AppRegistration.hostOf("https://share.example.net/oauth2/callback", "example.net"));
        assertEquals("example.net", AppRegistration.hostOf("https://example.net/", "example.net"));
        for (String bad : new String[] {"http://share.example.net/", "https://share.example.net.evil.example/",
                "https://notexample.net/", "https://share.example.net:8443/", "https://*.example.net/", "https://a@example.net/"}) {
            assertThrows(IllegalArgumentException.class, () -> AppRegistration.hostOf(bad, "example.net"), bad);
        }
    }

    // Live: the real DNS, validated from the root.

    static Resolver live() throws Exception {
        return AppRegistration.validating(System.getenv().getOrDefault("DNS_RESOLVER", "1.1.1.1"), null);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "LIVE_DNS", matches = "1")
    void liveSignedDomain() throws Exception {
        Resolver r = live();
        assertEquals(Answer.ABSENT, AppRegistration.validated(AppRegistration.ask(r, "isc.org", Type.TXT, true), HASH),
                "isc.org's TXT values validate, and none is our token");
        assertEquals(Answer.ABSENT, AppRegistration.validated(
                AppRegistration.ask(r, "_sustenaut-auth.isc.org", Type.TXT, true), HASH), "a validated: no such name");
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "LIVE_DNS", matches = "1")
    void liveBrokenSignatures() throws Exception {
        // dnssec-failed.org is broken on purpose (its keys don't match its DS at .org): nothing
        // in it validates, so never PRESENT and never a definite ABSENT that could revoke.
        Resolver r = live();
        assertEquals(Answer.UNKNOWN, AppRegistration.validated(AppRegistration.ask(r, "dnssec-failed.org", Type.TXT, true), HASH));
        assertEquals(Answer.UNKNOWN, AppRegistration.validated(
                AppRegistration.ask(r, "_sustenaut-auth.dnssec-failed.org", Type.TXT, true), HASH));
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "LIVE_DNS", matches = "1")
    void liveUnsignedDomain() throws Exception {
        // An unsigned domain can't approve anything (and can't revoke: no validated "no").
        // example.net and sustenaut.eu are unsigned until the DNS move; this prints which they are.
        Resolver r = live();
        // google.com is not signed.
        assertEquals(Answer.UNKNOWN, AppRegistration.validated(AppRegistration.ask(r, "google.com", Type.TXT, true), HASH));
        assertEquals(Answer.UNKNOWN, AppRegistration.validated(
                AppRegistration.ask(r, "_sustenaut-auth.google.com", Type.TXT, true), HASH));
        for (String domain : new String[] {"example.net", "sustenaut.eu"}) {
            Answer a = AppRegistration.validated(AppRegistration.ask(r, "_sustenaut-auth." + domain, Type.TXT, true), HASH);
            System.out.println("LIVE _sustenaut-auth." + domain + ": " + a + (a == Answer.UNKNOWN ? " (not signed yet)" : " (signed)"));
        }
    }
}
