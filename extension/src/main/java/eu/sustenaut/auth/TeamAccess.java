package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

/**
 * Who may use which team service, in a realm with {@value #ENABLED} (realm/team.json; never the
 * family realm). A person's access is the client roles they hold on the domain's sign-in client
 * (client id = the domain, AppRegistration), one role per service; the realm role
 * {@value #CONTROLLER} holds every service role and alone may change them (AccessPage). A site
 * declares its roles when it registers (AppRegistrationResource); an admin can declare them first
 * (AccessPage, import-team-access.sh): without a client yet they wait on a switched-off placeholder
 * with the domain's id (state {@value #DECLARED}) that a registration takes over. The token a
 * domain's client gets carries these in its access claim (AccessClaimMapper).
 */
final class TeamAccess {

    /** Realm attribute: this realm has service roles and the access page. */
    static final String ENABLED = "sustenaut.access.enabled";
    /** Realm attribute: the registrant's address (var.team_registrant), listed apart, no roles. */
    static final String REGISTRANT = "sustenaut.access.registrant";
    static final String CONTROLLER = "controller";
    /** A client's state (AppRegistration.STATE): roles declared, nothing registered yet. */
    static final String DECLARED = "declared";
    static final int MAX_ROLES = 50;
    /** The environment variable with the key of the access state's hash (stateHash). */
    static final String HASH_KEY = "SUSTENAUT_ACCESS_HASH_KEY";

    private TeamAccess() {}

    static boolean enabled(RealmModel realm) {
        return "true".equals(realm.getAttribute(ENABLED));
    }

    /** A service role's name: lower case, optional ":level", never the realm role's. */
    static boolean validRole(String role) {
        return role != null && role.length() <= 64 && !CONTROLLER.equals(role)
                && role.matches("[a-z][a-z0-9-]*(:[a-z][a-z0-9-]*)?");
    }

    /** The access claim: what the person holds on the client; a controller, all of them and "controller". */
    static List<String> claim(Collection<String> held, Collection<String> all, boolean controller) {
        TreeSet<String> out = new TreeSet<>(controller ? all : held);
        if (controller) {
            out.add(CONTROLLER);
        }
        return new ArrayList<>(out);
    }

    /** The claim of this person on this client, as it stands. */
    static List<String> claimOf(ClientModel client, UserModel user) {
        RoleModel controller = client.getRealm().getRole(CONTROLLER);
        return claim(client.getRolesStream().filter(user::hasRole).map(RoleModel::getName).toList(),
                client.getRolesStream().map(RoleModel::getName).toList(),
                controller != null && user.hasRole(controller));
    }

    /** One person's line in the access state. */
    static String stateLine(String userId, boolean enabled, int notBefore, List<String> claim) {
        return userId + " " + (enabled ? "on" : "off") + " " + notBefore + " " + String.join(",", claim);
    }

    /** The keyed hash of a client's access state: hex, the same for the same lines in any order, its own per client. */
    static String hash(String key, String clientId, List<String> lines) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            mac.update((clientId + "\n").getBytes(StandardCharsets.UTF_8));
            lines.stream().sorted().forEach(line -> mac.update((line + "\n").getBytes(StandardCharsets.UTF_8)));
            return HexFormat.of().formatHex(mac.doFinal());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The access state of a client, from Keycloak's state as it is now, so a change by any route
     * counts: everyone who holds something on it (the claim they would get), and every switched-off
     * account; with when their sessions were last ended by force. Signing in changes nothing here.
     */
    static String stateHash(KeycloakSession session, RealmModel realm, ClientModel client, String key) {
        List<String> lines = new ArrayList<>();
        session.users().searchForUserStream(realm, Map.of()).forEach(user -> {
            List<String> claim = claimOf(client, user);
            if (!user.isEnabled() || !claim.isEmpty()) {
                lines.add(stateLine(user.getId(), user.isEnabled(), session.users().getNotBeforeOfUser(realm, user), claim));
            }
        });
        return hash(key, client.getClientId(), lines);
    }

    static ProtocolMapperModel mapper() {
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setName(AccessClaimMapper.CLAIM);
        model.setProtocol("openid-connect");
        model.setProtocolMapper(AccessClaimMapper.PROVIDER_ID);
        model.setConfig(new HashMap<>(Map.of("id.token.claim", "true", "access.token.claim", "true",
                "userinfo.token.claim", "true", "introspection.token.claim", "true")));
        return model;
    }

    static void ensureMapper(ClientModel client) {
        if (client.getProtocolMappersStream().noneMatch(m -> AccessClaimMapper.PROVIDER_ID.equals(m.getProtocolMapper()))) {
            client.addProtocolMapper(mapper());
        }
    }

    /** Adds the roles the client lacks (and its mapper). Refuses what is not a role's name, or too many. */
    static void declare(ClientModel client, List<String> roles) {
        for (String role : roles) {
            if (!validRole(role)) {
                throw new IllegalArgumentException("roles: lower case names, an optional :level, not " + CONTROLLER + ": " + role);
            }
        }
        if (client.getRolesStream().map(RoleModel::getName).filter(r -> !roles.contains(r)).count()
                + roles.stream().distinct().count() > MAX_ROLES) {
            throw new IllegalArgumentException("roles: at most " + MAX_ROLES + " on a client");
        }
        roles.stream().filter(r -> client.getRole(r) == null).forEach(client::addRole);
        ensureMapper(client);
    }

    /** The domain's client that holds its roles: active or declared, under the domain's own id; else null. */
    static ClientModel clientOf(KeycloakSession session, RealmModel realm, String domain) {
        ClientModel client = session.clients().getClientByClientId(realm, domain);
        return client != null && ("active".equals(client.getAttribute(STATE)) || DECLARED.equals(client.getAttribute(STATE)))
                ? client : null;
    }

    /** The domain's client, or a switched-off placeholder for its roles when it has not registered yet. */
    static ClientModel clientOrPlaceholder(KeycloakSession session, RealmModel realm, String domain) {
        ClientModel client = clientOf(session, realm, domain);
        if (client == null) {
            client = realm.addClient(domain);
            client.setName(domain);
            client.setEnabled(false);
            client.setProtocol("openid-connect");
            client.setFullScopeAllowed(false);
            client.setAttribute(STATE, DECLARED);
            client.setAttribute(DOMAIN, domain);
        }
        return client;
    }

    /** The domain's latest revoked client, if it has one left (a failed re-check; kept 30 days): the list it held. */
    static ClientModel lastRevoked(KeycloakSession session, RealmModel realm, String domain) {
        return withState(session, realm, "revoked").filter(c -> domain.equals(c.getAttribute(DOMAIN)))
                .max(java.util.Comparator.comparingLong(c -> Long.parseLong(c.getAttribute(REVOKED).split(" ", 2)[0])))
                .orElse(null);
    }

    /** Who holds which of the client's roles: role name to user ids, before the client goes. */
    static Map<String, List<String>> holders(KeycloakSession session, RealmModel realm, ClientModel client) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        client.getRolesStream().forEach(role -> out.put(role.getName(),
                session.users().getRoleMembersStream(realm, role).map(UserModel::getId).toList()));
        return out;
    }

    /** A new registration takes over what the client before it held: its roles, and who holds them. */
    static void carryOver(KeycloakSession session, RealmModel realm, Map<String, List<String>> holders, ClientModel client) {
        holders.forEach((name, users) -> {
            RoleModel role = client.getRole(name) != null ? client.getRole(name) : client.addRole(name);
            for (String id : users) {
                UserModel user = session.users().getUserById(realm, id);
                if (user != null) {
                    user.grantRole(role);
                }
            }
        });
    }
}
