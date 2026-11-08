package eu.sustenaut.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The per-address limits on code emails and wrong codes (AddressBudget, FamilySignInForm). */
class AddressBudgetTest {

    static final long T = 1_793_180_000_000L;

    @Test
    void anHourFillsAndMovesOn() {
        AddressBudget budget = new AddressBudget(3, 100);
        for (int i = 0; i < 3; i++) {
            assertTrue(budget.allows("anna@example.org", T + i));
            budget.spend("anna@example.org", T + i);
        }
        assertFalse(budget.allows("anna@example.org", T + 10), "the fourth in the hour");
        assertFalse(budget.allows(" Anna@Example.org ", T + 10), "the same address, typed otherwise");
        assertTrue(budget.allows("bob@example.org", T + 10), "another address has its own");
        assertTrue(budget.allows("anna@example.org", T + AddressBudget.HOUR_MS + 2), "an hour on");
    }

    @Test
    void aDayFillsAcrossHours() {
        AddressBudget budget = new AddressBudget(10, 4);
        for (int i = 0; i < 4; i++) {
            budget.spend("anna@example.org", T + i * AddressBudget.HOUR_MS);
        }
        assertFalse(budget.allows("anna@example.org", T + 5 * AddressBudget.HOUR_MS), "four in the day");
        assertTrue(budget.allows("anna@example.org", T + AddressBudget.DAY_MS), "a day after the first");
    }

    @Test
    void addressesWithNothingInADayAreLetGo() {
        AddressBudget budget = new AddressBudget(10, 10);
        for (int i = 0; i <= AddressBudget.SWEEP_AT; i++) {
            budget.spend("p" + i + "@example.org", T);
        }
        budget.spend("late@example.org", T + AddressBudget.DAY_MS);
        assertEquals(1, budget.size());
    }

    @Test
    void theSignInFormsLimits() {
        // Six digits: at 30 wrong codes a day, about one chance in 90 a year.
        AddressBudget wrong = FamilySignInForm.WRONG_CODES;
        String who = "budget-test@example.org";
        for (int i = 0; i < 10; i++) {
            assertTrue(wrong.allows(who, T + i));
            wrong.spend(who, T + i);
        }
        assertFalse(wrong.allows(who, T + 11), "10 wrong codes an hour");
    }
}
