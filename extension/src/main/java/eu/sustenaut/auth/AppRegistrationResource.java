package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.ClientRegistrationTokenUtils;
import org.keycloak.services.clientregistration.policy.RegistrationAuth;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.ClientManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;

/**
 * /realms/&lt;realm&gt;/app-registration: a domain registers for sign-in, approved by its DNS
 * (AppRegistration explains the whole flow). Every call carries the registrant's access token
 * from the client app-registration (device flow): a verified email address exactly at the
 * domain.
 *
 * <pre>
 * POST /app-registration            {"domain": "example.net",
 *                                    "redirect_uris": ["https://share.example.net/oauth2/callback"],
 *                                    "post_logout_redirect_uris": ["https://share.example.net/"]}
 *                                    "roles": ["opportunity"]}   (realms with service roles, TeamAccess)
 *   201 {"id", "record": {"name", "type": "TXT", "value"}, "verify_url", "expires_at"}
 * POST /app-registration/{id}/verify
 *   409 not yet (the nameservers don't all have the record)
 *   200 {"client_id", "client_secret", "registration_access_token", "registration_client_uri", "issuer"}, once
 * </pre>
 *
 * <p>A registered domain then calls, with its client's id and secret (HTTP Basic):
 * PUT {domain}/settings, POST {domain}/invite, GET {domain}/people?email=, POST {domain}/remove,
 * POST {domain}/roles and GET {domain}/access-state (realms with service roles) and DELETE {domain}
 * (deregister).
 */
public class AppRegistrationResource implements RealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(AppRegistrationResource.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Accepted requests per registrant per hour (SUSTENAUT_APP_REQUESTS_PER_HOUR, default 10). */
    static final int PER_HOUR = perHour();
    private static final Map<String, List<Long>> RECENT = new ConcurrentHashMap<>();

    private final KeycloakSession session;

    AppRegistrationResource(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {}

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response request(String body) {
        RealmModel realm = session.getContext().getRealm();
        List<String> domains = domains(realm);
        if (domains.isEmpty()) {
            return error(404, "not_available", "this realm has no app registration");
        }
        UserModel registrant = registrant();
        if (registrant == null) {
            return error(401, "sign_in_required", "sign in first (client " + DEVICE_CLIENT
                    + ", device flow) and send the access token as a Bearer token");
        }
        Map<String, Object> in;
        try {
            in = JsonSerialization.readValue(body, Map.class);
        } catch (Exception e) {
            return error(400, "invalid_request", "a JSON object is required");
        }
        String domain = in.get("domain") instanceof String s ? s.trim().toLowerCase() : "";
        if (!domains.contains(domain)) {
            return error(400, "invalid_request", "domain must be one of " + String.join(", ", domains));
        }
        String email = registrant.getEmail() == null ? "" : registrant.getEmail().toLowerCase();
        if (!registrant.isEmailVerified() || !email.endsWith("@" + domain)) {
            return error(403, "not_at_domain", "registering " + domain + " needs a verified email address @"
                    + domain + "; you are signed in as " + email);
        }
        List<String> redirects = strings(in.get("redirect_uris"));
        List<String> logouts = strings(in.get("post_logout_redirect_uris"));
        List<String> roles = strings(in.get("roles"));
        List<String> origins = new ArrayList<>();
        try {
            if (redirects.isEmpty()) {
                throw new IllegalArgumentException("at least one redirect URI is required");
            }
            if (!roles.isEmpty() && !TeamAccess.enabled(realm)) {
                throw new IllegalArgumentException("this realm has no service roles");
            }
            for (String role : roles) {
                if (!TeamAccess.validRole(role)) {
                    throw new IllegalArgumentException("roles: lower case names, an optional :level, not "
                            + TeamAccess.CONTROLLER + ": " + role);
                }
            }
            for (String url : redirects) origins.add("https://" + hostOf(url, domain));
            for (String url : logouts) hostOf(url, domain);
        } catch (IllegalArgumentException e) {
            return error(400, "invalid_request", e.getMessage());
        }
        if (!allow(registrant.getId(), false)) {
            return error(429, "slow_down", "too many registration requests; try again in an hour");
        }
        long now = Instant.now().getEpochSecond();
        AppRegistrationResourceFactory.removeExpired(session, realm, now);
        if (withState(session, realm, "pending").count() >= MAX_PENDING) {
            return error(429, "slow_down", "too many registrations are waiting for their DNS record");
        }

        String id = random(16);
        String token = random(32);
        ClientRepresentation rep = new ClientRepresentation();
        rep.setClientId(PENDING_PREFIX + id);
        rep.setName(in.get("display_name") instanceof String d && !d.isBlank() ? d.trim() : domain);
        rep.setEnabled(false);
        rep.setProtocol("openid-connect");
        rep.setPublicClient(false);
        rep.setBearerOnly(false);
        rep.setClientAuthenticatorType("client-secret");
        rep.setStandardFlowEnabled(true);
        rep.setImplicitFlowEnabled(false);
        rep.setDirectAccessGrantsEnabled(false);
        rep.setServiceAccountsEnabled(false);
        rep.setFullScopeAllowed(false);
        rep.setConsentRequired(false);
        rep.setRedirectUris(redirects);
        rep.setWebOrigins(origins.stream().distinct().toList());
        rep.setBaseUrl(logouts.isEmpty() ? origins.get(0) + "/" : logouts.get(0));
        rep.setDefaultClientScopes(SCOPES);
        rep.setOptionalClientScopes(List.of());
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("pkce.code.challenge.method", "S256");
        if (!logouts.isEmpty()) {
            attributes.put("post.logout.redirect.uris", String.join("##", logouts));
        }
        attributes.put(STATE, "pending");
        attributes.put(DOMAIN, domain);
        attributes.put(EMAIL, email);
        attributes.put(REGISTRANT_ID, registrant.getId());
        attributes.put(TOKEN_HASH, sha256(token));
        attributes.put(EXPIRES, Long.toString(now + PENDING_SECONDS));
        rep.setAttributes(attributes);
        ClientModel created = ClientManager.createClient(session, realm, rep);
        if (TeamAccess.enabled(realm)) {
            TeamAccess.declare(created, roles);
        }
        allow(registrant.getId(), true);
        LOG.infof("app registration %s: %s asked by %s, waits for its DNS record", id, domain, email);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", id);
        out.put("record", Map.of("name", recordName(domain), "type", "TXT", "value", VALUE_PREFIX + token));
        out.put("verify_url", base(realm) + "/" + id + "/verify");
        out.put("expires_at", Instant.ofEpochSecond(now + PENDING_SECONDS).toString());
        return Response.status(201).entity(out).type(MediaType.APPLICATION_JSON).build();
    }

    @POST
    @Path("{id}/verify")
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@PathParam("id") String id) {
        RealmModel realm = session.getContext().getRealm();
        if (domains(realm).isEmpty()) {
            return error(404, "not_available", "this realm has no app registration");
        }
        UserModel registrant = registrant();
        if (registrant == null) {
            return error(401, "sign_in_required", "sign in first (client " + DEVICE_CLIENT + ", device flow)");
        }
        ClientModel client = id != null && id.matches("[0-9a-f]{32}")
                ? session.clients().getClientByClientId(realm, PENDING_PREFIX + id) : null;
        if (client == null || !"pending".equals(client.getAttribute(STATE))
                || !registrant.getId().equals(client.getAttribute(REGISTRANT_ID))) {
            // Unknown, already issued, or someone else's: all look the same.
            return error(404, "not_found", "no such registration waiting for you");
        }
        long now = Instant.now().getEpochSecond();
        if (now > Long.parseLong(client.getAttribute(EXPIRES))) {
            realm.removeClient(client.getId());
            return error(410, "expired", "this registration expired; ask again");
        }
        String domain = client.getAttribute(DOMAIN);
        Result result = lookup(realm, client);
        Answer answer = result.answer();
        if (answer != Answer.PRESENT) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", "pending");
            out.put("record", Map.of("name", recordName(domain), "type", "TXT"));
            out.put("message", (answer == Answer.ABSENT
                    ? "the TXT record is not there (or has another value); publish it and try again"
                    : "no definite answer yet; try again later") + " (" + result.why() + ")");
            return Response.status(409).entity(out).type(MediaType.APPLICATION_JSON).build();
        }
        ClientModel previous = session.clients().getClientByClientId(realm, domain);
        ClientModel listed = previous != null || !TeamAccess.enabled(realm) ? previous : TeamAccess.lastRevoked(session, realm, domain);
        Map<String, List<String>> holders = listed != null && TeamAccess.enabled(realm)
                ? TeamAccess.holders(session, realm, listed) : Map.of();
        if (previous != null) {
            // In a transaction of its own, committed first: the old client must have let go of
            // the name before this one takes it (one client id per realm, checked by the database).
            String previousId = previous.getId();
            boolean declared = TeamAccess.DECLARED.equals(previous.getAttribute(STATE));
            String why = "A new registration of " + domain + " by " + client.getAttribute(EMAIL) + " replaced this one.";
            KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), other -> {
                RealmModel otherRealm = other.realms().getRealm(realm.getId());
                other.getContext().setRealm(otherRealm);
                if (declared) {
                    otherRealm.removeClient(previousId); // only held roles, for this registration
                } else {
                    revoke(other, otherRealm, other.clients().getClientById(otherRealm, previousId), now, why);
                }
            });
        }
        TeamAccess.carryOver(session, realm, holders, client);
        client.setClientId(domain);
        client.setEnabled(true);
        client.setAttribute(STATE, "active");
        client.setAttribute(NEXT_CHECK, Long.toString(now + seconds(realm, CHECK_SECONDS, DEFAULT_CHECK_SECONDS)));
        client.setAttribute(MISSES, "0");
        client.removeAttribute(EXPIRES);
        String clientSecret = KeycloakModelUtils.generateSecret(client);
        String registrationToken = ClientRegistrationTokenUtils.updateRegistrationAccessToken(
                session, realm, client, RegistrationAuth.ANONYMOUS, List.of());
        LOG.infof("app registration %s: %s approved by DNS; client issued to %s", id, domain, client.getAttribute(EMAIL));

        String issuer = session.getContext().getUri(UrlType.FRONTEND).getBaseUri() + "realms/" + realm.getName();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("client_id", domain);
        out.put("client_secret", clientSecret);
        out.put("registration_access_token", registrationToken);
        out.put("registration_client_uri", issuer + "/clients-registrations/default/" + domain);
        out.put("issuer", issuer);
        return Response.ok(out).type(MediaType.APPLICATION_JSON).header("Cache-Control", "no-store").build();
    }

    // A registered domain manages its own settings and invites its own people, with its client's
    // id and secret (HTTP Basic), from wherever it keeps them (the domain's own server, say).

    /**
     * POST /app-registration/{domain}/roles {"roles": ["opportunity", "opportunity:owner"]}: a site
     * declares the service roles it understands (TeamAccess), in a realm that has them. Adding what
     * is there already changes nothing; a role is never taken away here, or given to anyone. The
     * answer lists all the client's roles.
     */
    @POST
    @Path("{domain}/roles")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response roles(@PathParam("domain") String domain, @jakarta.ws.rs.HeaderParam("Authorization") String authorization,
            String body) {
        RealmModel realm = session.getContext().getRealm();
        if (!TeamAccess.enabled(realm)) {
            return error(404, "not_available", "this realm has no service roles");
        }
        ClientModel client = domainClient(realm, domain, authorization);
        if (client == null) {
            return error(401, "unauthorized", "the domain's client id and secret are required (HTTP Basic)");
        }
        List<String> roles;
        try {
            Map<String, Object> in = JsonSerialization.readValue(body, Map.class);
            roles = strings(in.get("roles"));
            TeamAccess.declare(client, roles);
        } catch (IllegalArgumentException e) {
            return error(400, "invalid_request", e.getMessage());
        } catch (Exception e) {
            return error(400, "invalid_request", "a JSON object is required");
        }
        LOG.infof("app registration: %s declared its roles", client.getClientId());
        return Response.ok(Map.of("roles", client.getRolesStream().map(org.keycloak.models.RoleModel::getName).sorted().toList()))
                .type(MediaType.APPLICATION_JSON).build();
    }

    /**
     * GET /app-registration/{domain}/access-state: {"hash"}, a keyed hash of who holds what on this
     * client (TeamAccess.stateHash), worked out afresh from Keycloak's state. It says nothing of who
     * or what; a site compares it with the one it stored for a person, and asks userinfo only when
     * it differs (access_check.py). Only this client can read its own. 503 until the realm's key
     * (SUSTENAUT_ACCESS_HASH_KEY) is set.
     */
    @jakarta.ws.rs.GET
    @Path("{domain}/access-state")
    @Produces(MediaType.APPLICATION_JSON)
    public Response accessState(@PathParam("domain") String domain, @jakarta.ws.rs.HeaderParam("Authorization") String authorization) {
        RealmModel realm = session.getContext().getRealm();
        if (!TeamAccess.enabled(realm)) {
            return error(404, "not_available", "this realm has no service roles");
        }
        ClientModel client = domainClient(realm, domain, authorization);
        if (client == null) {
            return error(401, "unauthorized", "the domain's client id and secret are required (HTTP Basic)");
        }
        String key = System.getenv(TeamAccess.HASH_KEY);
        if (key == null || key.isBlank()) {
            LOG.warnf("app registration: %s is not set; no access state to give", TeamAccess.HASH_KEY);
            return error(503, "not_available", "the access state is not set up here");
        }
        return Response.ok(Map.of("hash", TeamAccess.stateHash(session, realm, client, key)))
                .type(MediaType.APPLICATION_JSON).header("Cache-Control", "no-store").build();
    }

    static final int NAME_MAX = 80, INTRO_MAX = 300, HELP_MAX = 80;
    static final int INVITES_PER_HOUR = 50;
    static final long INVITE_SECONDS = 7 * 24 * 3600;
    private static final Map<String, List<Long>> INVITES = new ConcurrentHashMap<>();

    /**
     * PUT /app-registration/{domain}/settings: what the domain's users see in the sign-in pages
     * and emails. {"display_name", "home_url", "invite_intro", "help_contact", "notify_url"}; all
     * plain text (no markup, no braces, no control characters), each within its limit; home_url
     * and notify_url https on the domain or under it. notify_url, if set, is told each of the
     * domain's people's first sign-in (SignInNotice). Replaces the domain's previous settings.
     */
    @jakarta.ws.rs.PUT
    @Path("{domain}/settings")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response settings(@PathParam("domain") String domain, @jakarta.ws.rs.HeaderParam("Authorization") String authorization,
            String body) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = domainClient(realm, domain, authorization);
        if (client == null) {
            return error(401, "unauthorized", "the domain's client id and secret are required (HTTP Basic)");
        }
        Map<String, Object> in;
        try {
            in = JsonSerialization.readValue(body, Map.class);
        } catch (Exception e) {
            return error(400, "invalid_request", "a JSON object is required");
        }
        Map<String, String> settings = new LinkedHashMap<>();
        try {
            settings.put(TENANT_NAME, text(in.get("display_name"), "display_name", NAME_MAX, true));
            settings.put(TENANT_INTRO, text(in.get("invite_intro"), "invite_intro", INTRO_MAX, false));
            settings.put(TENANT_HELP, text(in.get("help_contact"), "help_contact", HELP_MAX, false));
            String home = in.get("home_url") instanceof String h && !h.isBlank() ? h.trim() : null;
            if (home != null) {
                hostOf(home, client.getClientId());
            }
            settings.put(TENANT_HOME, home);
            String notify = in.get("notify_url") instanceof String n && !n.isBlank() ? n.trim() : null;
            if (notify != null) {
                hostOf(notify, client.getClientId());
            }
            settings.put(TENANT_NOTIFY, notify);
        } catch (IllegalArgumentException e) {
            return error(400, "invalid_request", e.getMessage());
        }
        settings.forEach((key, value) -> {
            if (value == null) client.removeAttribute(key); else client.setAttribute(key, value);
        });
        client.setName(settings.get(TENANT_NAME));
        if (settings.get(TENANT_HOME) != null) {
            client.setBaseUrl(settings.get(TENANT_HOME));
        }
        LOG.infof("app registration: %s updated its settings", client.getClientId());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("display_name", settings.get(TENANT_NAME));
        out.put("home_url", settings.get(TENANT_HOME));
        out.put("invite_intro", settings.get(TENANT_INTRO));
        out.put("help_contact", settings.get(TENANT_HELP));
        out.put("notify_url", settings.get(TENANT_NOTIFY));
        return Response.ok(out).type(MediaType.APPLICATION_JSON).build();
    }

    /**
     * POST /app-registration/{domain}/invite {"email", "first_name"?, "last_name"?}: invites
     * someone to sign in (no password; the email's link signs them in and lands them on the
     * domain's home page, once, within 7 days: FamilyInviteSignIn). Creates
     * the account if there is none (email verified: the domain vouches for it) and marks it with
     * the domain; an account that exists is marked too and gets a new invitation. The answer is
     * the same either way. The email is in the domain's words (its settings), from the realm's
     * address with the domain's name as sender.
     */
    @POST
    @Path("{domain}/invite")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response invite(@PathParam("domain") String domain, @jakarta.ws.rs.HeaderParam("Authorization") String authorization,
            String body) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = domainClient(realm, domain, authorization);
        if (client == null) {
            return error(401, "unauthorized", "the domain's client id and secret are required (HTTP Basic)");
        }
        Map<String, Object> in;
        try {
            in = JsonSerialization.readValue(body, Map.class);
        } catch (Exception e) {
            return error(400, "invalid_request", "a JSON object is required");
        }
        String email = in.get("email") instanceof String e ? e.trim().toLowerCase() : "";
        if (!email.matches("^[a-z0-9._%+-]+@([a-z0-9-]+\\.)+[a-z]{2,}$")) {
            return error(400, "invalid_request", "email: an email address");
        }
        String first, last;
        try {
            first = text(in.get("first_name"), "first_name", 80, false);
            last = text(in.get("last_name"), "last_name", 80, false);
        } catch (IllegalArgumentException e) {
            return error(400, "invalid_request", e.getMessage());
        }
        if (!count(INVITES, client.getClientId(), INVITES_PER_HOUR)) {
            return error(429, "slow_down", "too many invitations from " + client.getClientId() + "; try again in an hour");
        }
        UserModel user = session.users().getUserByEmail(realm, email);
        if (user == null) {
            user = session.users().addUser(realm, email);
            user.setEmail(email);
            user.setEmailVerified(true);
            user.setEnabled(true);
            if (first != null) user.setFirstName(first);
            if (last != null) user.setLastName(last);
            user.setSingleAttribute(NAMES_BY, client.getClientId());
            LOG.infof("app registration: %s invited a new person", client.getClientId());
        }
        if (!user.isEnabled() && user.getFirstAttribute(REMOVED_AT) != null) {
            // Switched off when its last domain let it go (FamilyRemoval), not locked by an admin:
            // invited again within the 30 days, it comes back as it was (passkeys too).
            user.setEnabled(true);
            user.removeAttribute(REMOVED_AT);
            LOG.infof("app registration: %s invited a removed account again; switched on", client.getClientId());
        }
        List<String> domains = new ArrayList<>(user.getAttributeStream(INVITED_BY).toList());
        if (!domains.contains(client.getClientId())) {
            domains.add(client.getClientId());
            user.setAttribute(INVITED_BY, domains);
        }
        if (user.isEnabled()) {
            int expiration = org.keycloak.common.util.Time.currentTime() + (int) INVITE_SECONDS;
            org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken token =
                    new org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken(
                            user.getId(), user.getEmail(), expiration, List.of(FamilyInviteSignIn.PROVIDER_ID), null,
                            client.getClientId());
            jakarta.ws.rs.core.UriBuilder link = org.keycloak.services.resources.LoginActionsService.actionTokenProcessor(
                    session.getContext().getUri());
            link.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));
            try {
                TenantEmail mail = new TenantEmail(session, client);
                mail.setUser(user);
                mail.setAttribute(org.keycloak.models.Constants.TEMPLATE_ATTR_REQUIRED_ACTIONS, token.getRequiredActions());
                mail.sendInvitation(link.build(realm.getName()).toString(), INVITE_SECONDS / 60);
            } catch (org.keycloak.email.EmailException e) {
                LOG.warnf(e, "app registration: %s's invitation could not be sent", client.getClientId());
                return error(503, "not_sent", "the invitation email could not be sent; try again later");
            }
        }
        // A disabled account (an admin locked it) gets nothing, and nobody is told.
        return Response.accepted(Map.of("status", "sent", "email", email)).type(MediaType.APPLICATION_JSON).build();
    }

    static final int LOOKUPS_PER_HOUR = 300;
    private static final Map<String, List<Long>> LOOKUPS = new ConcurrentHashMap<>();

    /**
     * GET /app-registration/{domain}/people?email=...: where someone the domain invited stands.
     * {"email", "status", "first_name"?, "last_name"?}: "active" (has signed in at least once, by any method: SignInRecorder),
     * "invited" (never signed in), or
     * "none": no account, a disabled one, or one this domain did not invite (a domain sees
     * only its own people, so the answer tells it nothing about anyone else's). The names only
     * to the domain that gave them ({@link #namesBy}).
     */
    @jakarta.ws.rs.GET
    @Path("{domain}/people")
    @Produces(MediaType.APPLICATION_JSON)
    public Response people(@PathParam("domain") String domain, @jakarta.ws.rs.HeaderParam("Authorization") String authorization,
            @jakarta.ws.rs.QueryParam("email") String given) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = domainClient(realm, domain, authorization);
        if (client == null) {
            return error(401, "unauthorized", "the domain's client id and secret are required (HTTP Basic)");
        }
        String email = given == null ? "" : given.trim().toLowerCase();
        if (!email.matches("^[a-z0-9._%+-]+@([a-z0-9-]+\\.)+[a-z]{2,}$")) {
            return error(400, "invalid_request", "email: an email address");
        }
        if (!count(LOOKUPS, client.getClientId(), LOOKUPS_PER_HOUR)) {
            return error(429, "slow_down", "too many lookups from " + client.getClientId() + "; try again in an hour");
        }
        UserModel user = session.users().getUserByEmail(realm, email);
        String status = "none";
        if (user != null && user.isEnabled() && user.getAttributeStream(INVITED_BY).anyMatch(client.getClientId()::equals)) {
            status = user.getFirstAttribute(SIGNED_IN) != null ? "active" : "invited";
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("email", email);
        out.put("status", status);
        if (!"none".equals(status) && client.getClientId().equals(namesBy(user))) {
            // As the domain gave them (invite), so it can carry them over (to a new address, say).
            // Only to the domain that gave them: another domain inviting the same person learns
            // nothing of what the first one wrote.
            if (user.getFirstName() != null) out.put("first_name", user.getFirstName());
            if (user.getLastName() != null) out.put("last_name", user.getLastName());
        }
        return Response.ok(out).type(MediaType.APPLICATION_JSON).header("Cache-Control", "no-store").build();
    }

    /** The domain that gave the account its names: NAMES_BY, or for older accounts the first to invite it. */
    static String namesBy(UserModel user) {
        String by = user.getFirstAttribute(NAMES_BY);
        return by != null ? by : user.getAttributeStream(INVITED_BY).findFirst().orElse(null);
    }

    static final int REMOVALS_PER_HOUR = 50;
    private static final Map<String, List<Long>> REMOVALS = new ConcurrentHashMap<>();

    /**
     * POST /app-registration/{domain}/remove {"email", "reason"?}: the domain lets someone go
     * (FamilyRemoval.leave): its mark comes off the account, all the person's sessions end, and
     * an account no domain lists any more is switched off (deleted after 30 days). The person is
     * emailed in the domain's words; reason "moved" (instead of the default "removed") says the
     * shares moved to a new address. Only people the domain invited are touched, and the answer
     * is the same for anyone (unknown, someone else's, already removed): 202.
     */
    @POST
    @Path("{domain}/remove")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response remove(@PathParam("domain") String domain, @jakarta.ws.rs.HeaderParam("Authorization") String authorization,
            String body) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = domainClient(realm, domain, authorization);
        if (client == null) {
            return error(401, "unauthorized", "the domain's client id and secret are required (HTTP Basic)");
        }
        Map<String, Object> in;
        try {
            in = JsonSerialization.readValue(body, Map.class);
        } catch (Exception e) {
            return error(400, "invalid_request", "a JSON object is required");
        }
        String email = in.get("email") instanceof String e ? e.trim().toLowerCase() : "";
        if (!email.matches("^[a-z0-9._%+-]+@([a-z0-9-]+\\.)+[a-z]{2,}$")) {
            return error(400, "invalid_request", "email: an email address");
        }
        FamilyRemoval.Reason reason = FamilyRemoval.Reason.fromApi(in.get("reason"));
        if (reason == null) {
            return error(400, "invalid_request", "reason: removed or moved");
        }
        if (!count(REMOVALS, client.getClientId(), REMOVALS_PER_HOUR)) {
            return error(429, "slow_down", "too many removals from " + client.getClientId() + "; try again in an hour");
        }
        UserModel user = session.users().getUserByEmail(realm, email);
        if (user != null) {
            FamilyRemoval.leave(session, realm, user, client, reason);
        }
        return Response.accepted(Map.of("status", "removed", "email", email)).type(MediaType.APPLICATION_JSON).build();
    }

    /**
     * DELETE /app-registration/{domain}: the domain deregisters. Its client is revoked now, as a
     * failed DNS check would (switched off, registrant told); after 30 days it is deleted and
     * the people it invited lose access (FamilyRemoval.domainGone).
     */
    @jakarta.ws.rs.DELETE
    @Path("{domain}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response deregister(@PathParam("domain") String domain, @jakarta.ws.rs.HeaderParam("Authorization") String authorization) {
        RealmModel realm = session.getContext().getRealm();
        ClientModel client = domainClient(realm, domain, authorization);
        if (client == null) {
            return error(401, "unauthorized", "the domain's client id and secret are required (HTTP Basic)");
        }
        long now = Instant.now().getEpochSecond();
        revoke(session, realm, client, now, domain + " asked (with its own credentials) to end its registration"
                + " with the authentication service " + serviceName() + ".");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "revoked");
        out.put("domain", domain);
        out.put("people_removed_at", Instant.ofEpochSecond(now + REVOKED_KEEP_SECONDS).toString());
        return Response.ok(out).type(MediaType.APPLICATION_JSON).build();
    }

    /** The active client of the domain, if the request carries its id and secret (HTTP Basic); else null. */
    private ClientModel domainClient(RealmModel realm, String domain, String authorization) {
        if (domains(realm).isEmpty() || authorization == null || !authorization.startsWith("Basic ")) {
            return null;
        }
        String decoded;
        try {
            decoded = new String(java.util.Base64.getDecoder().decode(authorization.substring(6).trim()),
                    java.nio.charset.StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        int colon = decoded.indexOf(':');
        if (colon < 0) {
            return null;
        }
        String id = java.net.URLDecoder.decode(decoded.substring(0, colon), java.nio.charset.StandardCharsets.UTF_8);
        String secret = java.net.URLDecoder.decode(decoded.substring(colon + 1), java.nio.charset.StandardCharsets.UTF_8);
        if (!id.equals(domain)) {
            return null;
        }
        ClientModel client = session.clients().getClientByClientId(realm, id);
        if (client == null || !client.isEnabled() || !"active".equals(client.getAttribute(STATE))
                || !domain.equals(client.getAttribute(DOMAIN)) || !client.validateSecret(secret)) {
            return null;
        }
        return client;
    }

    /** Plain text: trimmed, within the limit, no markup, braces or control characters. Null when empty. */
    static String text(Object value, String field, int max, boolean required) {
        String s = value instanceof String v ? v.strip() : null;
        if (s == null || s.isEmpty()) {
            if (required) throw new IllegalArgumentException(field + " is required");
            return null;
        }
        if (s.length() > max) throw new IllegalArgumentException(field + ": at most " + max + " characters");
        if (!s.matches("[^<>{}\\p{Cntrl}]+")) {
            throw new IllegalArgumentException(field + ": plain text only (no < > { } or control characters)");
        }
        return s;
    }

    private static boolean count(Map<String, List<Long>> recent, String who, int perHour) {
        long now = System.currentTimeMillis();
        List<Long> times = recent.computeIfAbsent(who, a -> new ArrayList<>());
        synchronized (times) {
            times.removeIf(t -> now - t > 3_600_000);
            if (times.size() >= perHour) return false;
            times.add(now);
            return true;
        }
    }

    /** The signed-in user of a Bearer access token issued to the app-registration client, or null. */
    private UserModel registrant() {
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null || auth.getUser() == null || !DEVICE_CLIENT.equals(auth.getToken().getIssuedFor())) {
            return null;
        }
        return auth.getUser();
    }

    private String base(RealmModel realm) {
        return session.getContext().getUri(UrlType.FRONTEND).getBaseUri() + "realms/" + realm.getName() + "/app-registration";
    }

    /** Whether the registrant may ask again; {@code record} counts an accepted request. */
    static boolean allow(String who, boolean record) {
        long now = System.currentTimeMillis();
        List<Long> times = RECENT.computeIfAbsent(who, a -> new ArrayList<>());
        synchronized (times) {
            times.removeIf(t -> now - t > 3_600_000);
            if (record) {
                times.add(now);
            }
            return times.size() < PER_HOUR;
        }
    }

    private static int perHour() {
        try {
            return Integer.parseInt(System.getenv().getOrDefault("SUSTENAUT_APP_REQUESTS_PER_HOUR", "10"));
        } catch (NumberFormatException e) {
            return 10;
        }
    }

    private static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        if (value instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof String s && !s.isBlank()) {
                    out.add(s.trim());
                }
            }
        }
        return out;
    }

    /** {@code bytes} random bytes as hex. */
    private static String random(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    private static Response error(int status, String error, String description) {
        return Response.status(status).entity(Map.of("error", error, "error_description", description))
                .type(MediaType.APPLICATION_JSON).build();
    }
}
