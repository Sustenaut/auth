package eu.sustenaut.auth;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * How often something may happen for one email address: at most {@code perHour} in any hour and
 * {@code perDay} in any day. Kept by address as typed (lower case), so an unknown address is
 * counted the same as a known one and the limit says nothing about who has an account.
 *
 * <p>In memory, like the other rate limits here: it starts afresh when Keycloak restarts, and
 * each replica keeps its own (one replica today).
 */
final class AddressBudget {

    static final long HOUR_MS = 3_600_000, DAY_MS = 24 * HOUR_MS;

    private final int perHour, perDay;
    private final Map<String, Deque<Long>> recent = new ConcurrentHashMap<>();

    AddressBudget(int perHour, int perDay) {
        this.perHour = perHour;
        this.perDay = perDay;
    }

    /** Whether there is room for one more now; does not count it. */
    boolean allows(String email, long nowMs) {
        Deque<Long> times = recent.get(key(email));
        if (times == null) {
            return perHour > 0 && perDay > 0;
        }
        synchronized (times) {
            forget(times, nowMs);
            return times.size() < perDay && within(times, nowMs, HOUR_MS) < perHour;
        }
    }

    /** Counts one more now. */
    void spend(String email, long nowMs) {
        if (recent.size() > SWEEP_AT) {
            sweep(nowMs);
        }
        Deque<Long> times = recent.computeIfAbsent(key(email), a -> new ArrayDeque<>());
        synchronized (times) {
            forget(times, nowMs);
            times.addLast(nowMs);
        }
    }

    /** Above this many addresses, those with nothing in the last day are let go. */
    static final int SWEEP_AT = 50_000;

    int size() {
        return recent.size();
    }

    private void sweep(long nowMs) {
        recent.entrySet().removeIf(entry -> {
            Deque<Long> times = entry.getValue();
            synchronized (times) {
                forget(times, nowMs);
                return times.isEmpty();
            }
        });
    }

    private static String key(String email) {
        return email == null ? "" : email.trim().toLowerCase(Locale.ROOT);
    }

    private static void forget(Deque<Long> times, long nowMs) {
        while (!times.isEmpty() && nowMs - times.peekFirst() >= DAY_MS) {
            times.removeFirst();
        }
    }

    private static long within(Deque<Long> times, long nowMs, long windowMs) {
        return times.stream().filter(t -> nowMs - t < windowMs).count();
    }
}
