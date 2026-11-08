package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import java.time.Instant;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.keycloak.timer.ScheduledTask;
import org.keycloak.timer.TimerProvider;

/**
 * Serves /realms/&lt;realm&gt;/app-registration (AppRegistrationResource) and runs the re-check.
 * Every tick (SUSTENAUT_APP_CHECK_TICK_SECONDS, default an hour) it goes through the realms with
 * app registration: requests past their 7 days are removed, revoked clients older than 30 days
 * deleted (their people let go first: FamilyRemoval.domainGone), accounts removed 30 days ago
 * deleted (once a day: FamilyRemoval.daily), and each active client due for a check (weekly, sustenaut.appRegistration.checkSeconds)
 * is looked up at the domain's nameservers (AppRegistration.lookup). There:
 * <ul>
 *   <li>the record is there: next check in a week;
 *   <li>a definite miss: checked again an hour later (sustenaut.appRegistration.retrySeconds); a
 *       second definite miss in a row revokes the client and tells the registrant;
 *   <li>no definite answer: checked again an hour later, nothing else changes.
 * </ul>
 * One Keycloak instance (KC_CACHE=local), so the task is not cluster-coordinated.
 */
public class AppRegistrationResourceFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "app-registration";
    private static final Logger LOG = Logger.getLogger(AppRegistrationResourceFactory.class);

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new AppRegistrationResource(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        long tick = tickSeconds();
        KeycloakModelUtils.runJobInTransaction(factory, session ->
                session.getProvider(TimerProvider.class).scheduleTask(
                        (ScheduledTask) AppRegistrationResourceFactory::checkAll, tick * 1000, "sustenaut-app-registration-check"));
        LOG.infof("app registration: due DNS records checked every %d s", tick);
    }

    static long tickSeconds() {
        try {
            return Math.max(1, Long.parseLong(System.getenv().getOrDefault("SUSTENAUT_APP_CHECK_TICK_SECONDS", "3600")));
        } catch (NumberFormatException e) {
            return 3600;
        }
    }

    static void checkAll(KeycloakSession session) {
        long now = Instant.now().getEpochSecond();
        session.realms().getRealmsStream().filter(r -> !domains(r).isEmpty()).toList().forEach(realm -> {
            session.getContext().setRealm(realm);
            removeExpired(session, realm, now);
            FamilyRemoval.daily(session, realm, now);
            withState(session, realm, "active").toList().forEach(client -> checkOne(session, realm, client, now));
        });
    }

    static void removeExpired(KeycloakSession session, RealmModel realm, long now) {
        withState(session, realm, "pending")
                .filter(c -> now > Long.parseLong(c.getAttribute(EXPIRES)))
                .map(ClientModel::getId).toList()
                .forEach(realm::removeClient);
        withState(session, realm, "revoked")
                .filter(c -> now - Long.parseLong(c.getAttribute(REVOKED).split(" ", 2)[0]) > REVOKED_KEEP_SECONDS)
                .toList()
                .forEach(c -> {
                    // Its people lose access first (FamilyRemoval), unless the domain registered again.
                    FamilyRemoval.domainGone(session, realm, c);
                    realm.removeClient(c.getId());
                });
    }

    static void checkOne(KeycloakSession session, RealmModel realm, ClientModel client, long now) {
        String next = client.getAttribute(NEXT_CHECK);
        if (next != null && now < Long.parseLong(next)) {
            return;
        }
        long retry = seconds(realm, RETRY_SECONDS, DEFAULT_RETRY_SECONDS);
        String domain = client.getAttribute(DOMAIN);
        Result result = lookup(realm, client);
        switch (result.answer()) {
            case PRESENT -> {
                client.setAttribute(MISSES, "0");
                client.setAttribute(NEXT_CHECK, Long.toString(now + seconds(realm, CHECK_SECONDS, DEFAULT_CHECK_SECONDS)));
            }
            case ABSENT -> {
                int misses = Integer.parseInt(client.getAttribute(MISSES) == null ? "0" : client.getAttribute(MISSES)) + 1;
                if (misses >= MISSES_TO_REVOKE) {
                    revoke(session, realm, client, now, "The TXT record " + recordName(domain)
                            + " required to use the authentication service " + serviceName() + " no longer exists"
                            + " (or no longer has the value given at registration).");
                } else {
                    LOG.warnf("app registration: %s is missing (%s); asking again in %d s",
                            recordName(domain), result.why(), retry);
                    client.setAttribute(MISSES, Integer.toString(misses));
                    client.setAttribute(NEXT_CHECK, Long.toString(now + retry));
                }
            }
            case UNKNOWN -> {
                LOG.warnf("app registration: no definite answer for %s (%s); asking again in %d s",
                        recordName(domain), result.why(), retry);
                client.setAttribute(NEXT_CHECK, Long.toString(now + retry));
            }
        }
    }

    @Override
    public void close() {}
}
