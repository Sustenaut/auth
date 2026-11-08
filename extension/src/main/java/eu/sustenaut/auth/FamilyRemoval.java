package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

/**
 * Someone stops having access to a registered domain: the domain removes them
 * (AppRegistrationResource /remove, reason "removed" or "moved"), they leave it themselves
 * (LeaveDomainAction, "left"), or the domain's revoked client reaches its deletion ("gone").
 *
 * <p>{@link #leave} drops the domain from the account's {@value AppRegistration#INVITED_BY} and
 * ends all of the person's sessions, offline ones too. An account no domain lists any more is
 * switched off and stamped {@value AppRegistration#REMOVED_AT} (passkeys kept: a new invitation
 * within 30 days switches it on again as it was); {@link #daily} deletes it after 30 days. An
 * account switched off without the stamp (an admin locked it) is never deleted by this.
 */
final class FamilyRemoval {

    private static final Logger LOG = Logger.getLogger(FamilyRemoval.class);

    /** Why access ends; changes only the email's wording. */
    enum Reason {
        REMOVED, MOVED, LEFT, GONE;

        String word() {
            return name().toLowerCase();
        }

        /** From the API's "reason": removed (also when absent) or moved; null for anything else. */
        static Reason fromApi(Object value) {
            if (value == null) return REMOVED;
            return "removed".equals(value) ? REMOVED : "moved".equals(value) ? MOVED : null;
        }
    }

    enum Outcome { NOT_MARKED, KEPT, DISABLED }

    private static final Map<String, Long> LAST_DAILY = new ConcurrentHashMap<>();

    private FamilyRemoval() {}

    /** The account's domains without this one; null if this one is not among them. */
    static List<String> without(List<String> invitedBy, String domain) {
        if (domain == null || !invitedBy.contains(domain)) {
            return null;
        }
        List<String> left = new ArrayList<>(invitedBy);
        left.removeIf(domain::equals);
        return left;
    }

    /** Whether an account stamped removed at {@code removedAt} is due for deletion. */
    static boolean due(String removedAt, long now) {
        try {
            return removedAt != null && now - Long.parseLong(removedAt.trim()) >= DELETE_AFTER_SECONDS;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /** Ends {@code user}'s access to the domain of {@code domainClient} (active or revoked); see above. */
    static Outcome leave(KeycloakSession session, RealmModel realm, UserModel user, ClientModel domainClient, Reason reason) {
        String domain = domainClient.getAttribute(DOMAIN);
        List<String> left = without(user.getAttributeStream(INVITED_BY).toList(), domain);
        if (left == null) {
            return Outcome.NOT_MARKED;
        }
        if (left.isEmpty()) {
            user.removeAttribute(INVITED_BY);
        } else {
            user.setAttribute(INVITED_BY, left);
        }
        endSessions(session, realm, user);
        boolean disable = left.isEmpty() && user.isEnabled();
        if (disable) {
            user.setEnabled(false);
            user.setSingleAttribute(REMOVED_AT, Long.toString(Time.currentTime()));
        }
        // An account an admin locked stays locked and unstamped; it is not told anything either.
        LOG.infof("family removal: %s, %s, account %s", domain, reason.word(), disable ? "disabled" : "kept");
        if (disable || user.isEnabled()) {
            tell(session, realm, user, domainClient, reason, disable);
        }
        return disable ? Outcome.DISABLED : Outcome.KEPT;
    }

    /** Every session of the person ends, offline ones too, and tokens issued before now stop working. */
    static void endSessions(KeycloakSession session, RealmModel realm, UserModel user) {
        session.users().setNotBeforeForUser(realm, user, Time.currentTime());
        for (UserSessionModel s : session.sessions().getUserSessionsStream(realm, user).toList()) {
            session.sessions().removeUserSession(realm, s);
        }
        for (UserSessionModel s : session.sessions().getOfflineUserSessionsStream(realm, user).toList()) {
            session.sessions().removeOfflineUserSession(realm, s);
        }
    }

    /** The variables of family-removed.ftl: the message is familyRemoved_&lt;reason&gt;, plus the deletion line if disabled. */
    static Map<String, Object> notice(String domain, String name, Reason reason, boolean disabled) {
        Map<String, Object> body = new HashMap<>();
        body.put("domain", domain);
        body.put("domainName", name);
        body.put("reason", reason.word());
        body.put("disabled", disabled);
        body.put("deleteDays", DELETE_AFTER_SECONDS / 86400);
        return body;
    }

    private static void tell(KeycloakSession session, RealmModel realm, UserModel user, ClientModel domainClient,
            Reason reason, boolean disabled) {
        if (user.getEmail() == null) {
            return;
        }
        try {
            session.getContext().setRealm(realm);
            TenantEmail mail = new TenantEmail(session, domainClient);
            mail.setUser(user);
            String domain = domainClient.getAttribute(DOMAIN);
            String name = mail.tenantName() == null ? domain : mail.tenantName();
            mail.sendTenant("familyRemovedSubject", List.of(name), "family-removed.ftl", notice(domain, name, reason, disabled));
        } catch (EmailException | RuntimeException e) {
            LOG.warnf(e, "family removal: the email about %s could not be sent", domainClient.getAttribute(DOMAIN));
        }
    }

    /**
     * Before a revoked client is deleted: everyone it still lists loses access, unless the domain
     * has registered again since (an active client of the same domain keeps them).
     */
    static void domainGone(KeycloakSession session, RealmModel realm, ClientModel revoked) {
        String domain = revoked.getAttribute(DOMAIN);
        if (domain == null || withState(session, realm, "active").anyMatch(c -> domain.equals(c.getAttribute(DOMAIN)))) {
            return;
        }
        session.users().searchForUserByUserAttributeStream(realm, INVITED_BY, domain).toList()
                .forEach(user -> leave(session, realm, user, revoked, Reason.GONE));
    }

    /**
     * Once a day (the realm's removalSeconds) per realm: accounts stamped removed 30 or more
     * days ago are deleted. The last run is kept in memory (one instance); a restart runs it again.
     */
    static void daily(KeycloakSession session, RealmModel realm, long now) {
        long every = seconds(realm, REMOVAL_SECONDS, DEFAULT_REMOVAL_SECONDS);
        Long last = LAST_DAILY.get(realm.getId());
        if (last != null && now - last < every) {
            return;
        }
        LAST_DAILY.put(realm.getId(), now);
        UserManager users = new UserManager(session);
        session.users().searchForUserStream(realm, Map.of(UserModel.ENABLED, "false")).toList().stream()
                .filter(u -> due(u.getFirstAttribute(REMOVED_AT), now))
                .forEach(u -> {
                    users.removeUser(realm, u);
                    LOG.infof("family removal: an account removed %d days ago is deleted", DELETE_AFTER_SECONDS / 86400);
                });
    }
}
