package eu.sustenaut.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class TeamAccessTest {

    @Test
    void theClaimIsWhatThePersonHolds() {
        assertEquals(List.of("opportunity"), TeamAccess.claim(List.of("opportunity"), List.of("opportunity", "release"), false));
        assertEquals(List.of(), TeamAccess.claim(List.of(), List.of("opportunity"), false));
    }

    @Test
    void aControllerGetsEveryRoleAndTheWord() {
        assertEquals(List.of("controller", "opportunity", "release"),
                TeamAccess.claim(List.of(), List.of("release", "opportunity"), true));
        assertEquals(List.of("controller"), TeamAccess.claim(List.of(), List.of(), true));
    }

    @Test
    void theStateHash() {
        List<String> state = List.of(TeamAccess.stateLine("a", true, 0, List.of("opportunity")),
                TeamAccess.stateLine("b", false, 7, List.of()));
        String hash = TeamAccess.hash("key", "sustenaut.eu", state);
        assertTrue(hash.matches("[0-9a-f]{64}"), hash);
        assertEquals(hash, TeamAccess.hash("key", "sustenaut.eu", List.of(state.get(1), state.get(0))));
        assertFalse(hash.equals(TeamAccess.hash("other", "sustenaut.eu", state)));
        assertFalse(hash.equals(TeamAccess.hash("key", "example.org", state)));
        assertFalse(hash.equals(TeamAccess.hash("key", "sustenaut.eu", List.of(state.get(0)))));
        assertFalse(hash.equals(TeamAccess.hash("key", "sustenaut.eu",
                List.of(TeamAccess.stateLine("a", true, 0, List.of()), state.get(1)))));
        assertFalse(hash.equals(TeamAccess.hash("key", "sustenaut.eu",
                List.of(state.get(0), TeamAccess.stateLine("b", true, 7, List.of())))));
    }

    @Test
    void roleNames() {
        for (String good : List.of("opportunity", "release:operator", "a-b1")) {
            assertTrue(TeamAccess.validRole(good), good);
        }
        for (String bad : List.of("controller", "", "Upper", "1a", "a b", "a:b:c", "a/b", "<x>", "x".repeat(65))) {
            assertFalse(TeamAccess.validRole(bad), bad);
        }
    }

    @Test
    void status() {
        assertEquals("removed", AccessPage.status(false, true, true));
        assertEquals("active", AccessPage.status(true, true, false));
        assertEquals("active", AccessPage.status(true, false, true));
        assertEquals("invited", AccessPage.status(true, false, false));
    }
}
