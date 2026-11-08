package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.ClientModel;

/** LeaveDomainAction's decisions without Keycloak running: where confirming lands, and why a client is refused. */
class LeaveDomainActionTest {

    static ClientModel client(String clientId, boolean enabled, Map<String, String> attributes) {
        return FamilyRemovalTest.proxy(ClientModel.class, (method, args) -> switch (method) {
            case "getClientId" -> clientId;
            case "isEnabled" -> enabled;
            case "getAttribute" -> attributes.get(args[0]);
            default -> null;
        });
    }

    @Test
    void confirmingGoesBackToTheAppWithTheOutcomeAndItsStateButNoCode() {
        assertEquals("https://share.example.net/left?state=abc&kc_action=sustenaut-leave&kc_action_status=success",
                LeaveDomainAction.landing("https://share.example.net/left", "abc").toString());
        assertEquals("https://share.example.net/left?x=1&kc_action=sustenaut-leave&kc_action_status=success",
                LeaveDomainAction.landing("https://share.example.net/left?x=1", null).toString(), "no state: none sent");
    }

    @Test
    void onlyARegisteredDomainsActiveClientCounts() {
        List<String> domains = List.of("example.net", "sustenaut.eu");
        Map<String, String> active = Map.of(STATE, "active", DOMAIN, "example.net");
        assertNull(LeaveDomainAction.notADomain(client("example.net", true, active), domains));
        assertEquals("no client", LeaveDomainAction.notADomain(null, domains));
        assertEquals("client switched off", LeaveDomainAction.notADomain(client("example.net", false, active), domains));
        assertEquals("client not an active registration", LeaveDomainAction.notADomain(
                client("example.net", true, Map.of(STATE, "revoked", DOMAIN, "example.net")), domains));
        assertEquals("client not an active registration", LeaveDomainAction.notADomain(client("test-app", true, Map.of()), domains));
        assertEquals("client id is not its domain", LeaveDomainAction.notADomain(
                client("revoked-example.net-1", true, active), domains));
        assertEquals("domain not allowed in this realm", LeaveDomainAction.notADomain(
                client("example.net", true, active), List.of("sustenaut.eu")));
    }
}
