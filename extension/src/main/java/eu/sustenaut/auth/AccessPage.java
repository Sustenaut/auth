package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.actiontoken.execactions.ExecuteActionsActionToken;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AuthDetails;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;

/**
 * /realms/&lt;realm&gt;/access: who may use which team service (TeamAccess), for a controller only,
 * in a realm with access enabled (404 elsewhere). Signed in through the realm's own browser flow:
 * no session sends the browser through the client team-access (realm/team.json), which comes back
 * here; the session cookie is what counts, the code is thrown away. Someone else signed in gets a
 * refusal. Plain forms, no script.
 *
 * <p>Every change is a POST with the session's own token (a note on the user session) and, as
 * browsers send it, an Origin of this server's address. Each is written to the realm's admin events
 * (with the admin API's own changes, so the admin console's and the scripts' show too), which is the
 * page's history per person; they are kept a year (adminEventsExpiration, realm/team.json).
 *
 * <p>A tick is a role; taking it off changes only that, at the person's next sign-in or token
 * refresh. "Remove from all" takes every role, ends all their sessions and switches the account off
 * with the stamp FamilyRemoval's daily job deletes it by 30 days later; putting them back before
 * then restores the account, passkeys included, without its roles. A controller cannot take
 * controller off themself or remove themself, so there is always one left.
 */
public class AccessPage implements RealmResourceProvider {

    private static final Logger LOG = Logger.getLogger(AccessPage.class);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String CSRF_NOTE = "sustenaut.access.csrf";
    static final String LOGIN_CLIENT = "team-access";
    private static final String PASSKEY_SETUP = "webauthn-register-passwordless";
    private static final DateTimeFormatter WHEN = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);
    private static final int HISTORY = 30;
    private static final int MAX_PEOPLE = 500;

    private final KeycloakSession session;

    AccessPage(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {}

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response page() {
        RealmModel realm = session.getContext().getRealm();
        if (!TeamAccess.enabled(realm)) {
            return Response.status(404).build();
        }
        var query = session.getContext().getUri().getQueryParameters();
        AuthenticationManager.AuthResult auth = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
        if (auth == null) {
            return Response.seeOther(signIn(realm)).build();
        }
        if (query.containsKey("code") || query.containsKey("error")) {
            return Response.seeOther(URI.create(self(realm))).build(); // back from the sign-in: a clean address
        }
        if (!isController(realm, auth.getUser())) {
            LOG.info("access page: refused someone without the controller role");
            return html(403, form(realm, auth.getUser()).setAttribute("refused", true));
        }
        String done = query.getFirst("done");
        LoginFormsProvider form = form(realm, auth.getUser())
                .setAttribute("refused", false)
                .setAttribute("csrf", csrf(auth.getSession()))
                .setAttribute("done", done != null && done.matches("[a-zA-Z]{1,30}") ? done : "")
                .setAttribute("me", auth.getUser().getId())
                .setAttribute("domains", domains(realm))
                .setAttribute("columns", columns(realm));
        List<Map<String, Object>> people = new ArrayList<>();
        List<Map<String, Object>> apart = new ArrayList<>();
        session.users().searchForUserStream(realm, Map.of(), 0, MAX_PEOPLE)
                .sorted(Comparator.comparing(u -> String.valueOf(u.getEmail())))
                .forEach(user -> (isRegistrant(realm, user) ? apart : people).add(person(realm, user)));
        return html(200, form.setAttribute("people", people).setAttribute("registrants", apart));
    }

    /** Ticks a service role, or controller. */
    @POST
    @Path("grant")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response grant() {
        return change((realm, me, form) -> {
            UserModel user = target(realm, form);
            RoleModel role = role(realm, form);
            if (user == null || role == null || !user.isEnabled() || isRegistrant(realm, user)) {
                return "notChanged";
            }
            if (!user.hasDirectRole(role)) {
                user.grantRole(role);
                history(realm, me, user, OperationType.CREATE, "gave " + role.getName());
            }
            return "granted";
        });
    }

    /** Takes a tick off: this service only, nothing else about the person changes. */
    @POST
    @Path("revoke")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response revoke() {
        return change((realm, me, form) -> {
            UserModel user = target(realm, form);
            RoleModel role = role(realm, form);
            if (user == null || role == null) {
                return "notChanged";
            }
            if (TeamAccess.CONTROLLER.equals(role.getName()) && !role.isClientRole() && user.getId().equals(me.getId())) {
                return "notYourself";
            }
            if (user.hasDirectRole(role)) {
                user.deleteRoleMapping(role);
                history(realm, me, user, OperationType.DELETE, "took " + role.getName() + " away");
            }
            return "revoked";
        });
    }

    /** Takes every role, ends all their sessions, switches the account off (kept 30 days). */
    @POST
    @Path("remove")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response remove() {
        return change((realm, me, form) -> {
            UserModel user = target(realm, form);
            if (user == null || isRegistrant(realm, user)) {
                return "notChanged";
            }
            if (user.getId().equals(me.getId())) {
                return "notYourself";
            }
            user.getRoleMappingsStream()
                    .filter(r -> r.isClientRole() || TeamAccess.CONTROLLER.equals(r.getName()))
                    .toList().forEach(user::deleteRoleMapping);
            FamilyRemoval.endSessions(session, realm, user);
            if (user.isEnabled()) {
                user.setEnabled(false);
                user.setSingleAttribute(REMOVED_AT, Long.toString(Time.currentTime()));
            }
            history(realm, me, user, OperationType.DELETE, "removed from everything: signed out and switched off");
            return "removed";
        });
    }

    /** A removed person back: the account as it was (passkeys too), no roles, a new invitation. */
    @POST
    @Path("restore")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response restore() {
        return change((realm, me, form) -> {
            UserModel user = target(realm, form);
            if (user == null) {
                return "notChanged";
            }
            user.setEnabled(true);
            user.removeAttribute(REMOVED_AT);
            history(realm, me, user, OperationType.UPDATE, "put back");
            return invite(realm, user) ? "restored" : "notSent";
        });
    }

    /** Sends someone's invitation again (a new phone, say). */
    @POST
    @Path("resend")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response resend() {
        return change((realm, me, form) -> {
            UserModel user = target(realm, form);
            if (user == null || !user.isEnabled()) {
                return "notChanged";
            }
            history(realm, me, user, OperationType.ACTION, "sent the invitation again");
            return invite(realm, user) ? "invited" : "notSent";
        });
    }

    /** Email, name, ticks: an account if there is none (verified: the controller vouches), and the invitation. */
    @POST
    @Path("invite")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response inviteSomeone() {
        return change((realm, me, form) -> {
            String email = form.getFirst("email") == null ? "" : form.getFirst("email").trim().toLowerCase(Locale.ROOT);
            if (!email.matches("^[a-z0-9._%+-]+@([a-z0-9-]+\\.)+[a-z]{2,}$")) {
                return "badEmail";
            }
            String first;
            String last;
            try {
                first = AppRegistrationResource.text(form.getFirst("first_name"), "first_name", 80, false);
                last = AppRegistrationResource.text(form.getFirst("last_name"), "last_name", 80, false);
            } catch (IllegalArgumentException e) {
                return "badName";
            }
            UserModel user = session.users().getUserByEmail(realm, email);
            if (user != null && isRegistrant(realm, user)) {
                return "notChanged";
            }
            if (user == null) {
                user = session.users().addUser(realm, email);
                user.setEmail(email);
                user.setEmailVerified(true);
                user.setEnabled(true);
                if (first != null) user.setFirstName(first);
                if (last != null) user.setLastName(last);
            } else if (!user.isEnabled()) {
                user.setEnabled(true);
                user.removeAttribute(REMOVED_AT);
            }
            history(realm, me, user, OperationType.CREATE, "invited");
            List<String> ticked = form.get("role") == null ? List.of() : form.get("role");
            for (String pair : ticked) {
                RoleModel role = role(realm, pair);
                if (role != null && !user.hasDirectRole(role)) {
                    user.grantRole(role);
                    history(realm, me, user, OperationType.CREATE, "gave " + role.getName());
                }
            }
            return invite(realm, user) ? "invited" : "notSent";
        });
    }

    /** Declares a service role (a new column), on the domain's client or, before it registers, a placeholder. */
    @POST
    @Path("declare")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response declare() {
        return change((realm, me, form) -> {
            String domain = form.getFirst("domain");
            String name = form.getFirst("name") == null ? "" : form.getFirst("name").trim();
            if (domain == null || !domains(realm).contains(domain) || !TeamAccess.validRole(name)) {
                return "badRole";
            }
            try {
                TeamAccess.declare(TeamAccess.clientOrPlaceholder(session, realm, domain), List.of(name));
            } catch (IllegalArgumentException e) {
                return "badRole";
            }
            LOG.infof("access page: the role %s declared on %s", name, domain);
            return "declared";
        });
    }

    private interface Change {
        String run(RealmModel realm, UserModel me, MultivaluedMap<String, String> form);
    }

    /** A controller's change, with the session's token, from this server's own page; else refused, unchanged. */
    private Response change(Change change) {
        RealmModel realm = session.getContext().getRealm();
        if (!TeamAccess.enabled(realm)) {
            return Response.status(404).build();
        }
        AuthenticationManager.AuthResult auth = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
        if (auth == null) {
            return Response.seeOther(signIn(realm)).build();
        }
        if (!isController(realm, auth.getUser())) {
            LOG.info("access page: a change refused: no controller role");
            return Response.status(403).type(MediaType.TEXT_PLAIN).entity("Only a controller can change access.\n").build();
        }
        MultivaluedMap<String, String> form = session.getContext().getHttpRequest().getDecodedFormParameters();
        String origin = session.getContext().getRequestHeaders().getHeaderString("Origin");
        String note = auth.getSession().getNote(CSRF_NOTE);
        String given = form.getFirst("csrf");
        if ((origin != null && !origin.equals(origin(realm))) || note == null || given == null
                || !MessageDigest.isEqual(note.getBytes(StandardCharsets.UTF_8), given.getBytes(StandardCharsets.UTF_8))) {
            LOG.warn("access page: a change refused: wrong token or origin");
            return Response.status(403).type(MediaType.TEXT_PLAIN).entity("This form has expired; open the page again.\n").build();
        }
        String done = change.run(realm, auth.getUser(), form);
        return Response.seeOther(URI.create(self(realm) + "?done=" + done)).build();
    }

    private boolean invite(RealmModel realm, UserModel user) {
        // The link's "back to" page is the domain's client, when it has one that is switched on.
        ClientModel client = domains(realm).stream().map(d -> TeamAccess.clientOf(session, realm, d))
                .filter(c -> c != null && c.isEnabled()).findFirst().orElse(null);
        String clientId = client != null ? client.getClientId() : DEVICE_CLIENT;
        int expiration = Time.currentTime() + (int) AppRegistrationResource.INVITE_SECONDS;
        ExecuteActionsActionToken token = new ExecuteActionsActionToken(user.getId(), user.getEmail(), expiration,
                List.of(PASSKEY_SETUP), null, clientId);
        var link = LoginActionsService.actionTokenProcessor(session.getContext().getUri());
        link.queryParam("key", token.serialize(session, realm, session.getContext().getUri()));
        try {
            TenantEmail mail = new TenantEmail(session, client);
            mail.setUser(user);
            mail.setAttribute(Constants.TEMPLATE_ATTR_REQUIRED_ACTIONS, token.getRequiredActions());
            mail.sendInvitation(link.build(realm.getName()).toString(), AppRegistrationResource.INVITE_SECONDS / 60);
            return true;
        } catch (EmailException e) {
            LOG.warn("access page: an invitation could not be sent", e);
            return false;
        }
    }

    private Map<String, Object> person(RealmModel realm, UserModel user) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", user.getId());
        out.put("email", String.valueOf(user.getEmail()));
        out.put("name", ((user.getFirstName() == null ? "" : user.getFirstName()) + " "
                + (user.getLastName() == null ? "" : user.getLastName())).trim());
        out.put("status", status(user));
        String removed = user.getFirstAttribute(REMOVED_AT);
        out.put("deleteOn", !user.isEnabled() && removed != null && removed.matches("\\d+")
                ? DAY.format(Instant.ofEpochSecond(Long.parseLong(removed) + DELETE_AFTER_SECONDS)) : "");
        boolean controller = isController(realm, user);
        out.put("controller", controller);
        List<Map<String, Object>> ticks = new ArrayList<>();
        for (Map<String, String> column : columns(realm)) {
            RoleModel role = role(realm, column.get("key"));
            Map<String, Object> tick = new LinkedHashMap<>();
            tick.put("key", column.get("key"));
            tick.put("label", column.get("label"));
            tick.put("held", role != null && user.hasRole(role));
            ticks.add(tick);
        }
        out.put("ticks", ticks);
        out.put("history", history(realm, user));
        return out;
    }

    /** invited (never signed in, no passkey yet), active, or removed (switched off). */
    static String status(boolean enabled, boolean signedIn, boolean hasCredential) {
        return !enabled ? "removed" : signedIn || hasCredential ? "active" : "invited";
    }

    private String status(UserModel user) {
        return status(user.isEnabled(), user.getFirstAttribute(SIGNED_IN) != null,
                user.credentialManager().getStoredCredentialsStream().findAny().isPresent());
    }

    private List<Map<String, String>> columns(RealmModel realm) {
        List<Map<String, String>> out = new ArrayList<>();
        for (String domain : domains(realm)) {
            ClientModel client = TeamAccess.clientOf(session, realm, domain);
            if (client != null) {
                client.getRolesStream().map(RoleModel::getName).sorted().forEach(name ->
                        out.add(Map.of("key", domain + "/" + name, "label", name, "domain", domain)));
            }
        }
        return out;
    }

    private UserModel target(RealmModel realm, MultivaluedMap<String, String> form) {
        String id = form.getFirst("user");
        return id == null ? null : session.users().getUserById(realm, id);
    }

    private RoleModel role(RealmModel realm, MultivaluedMap<String, String> form) {
        return role(realm, form.getFirst("role"));
    }

    /** "domain/role" (a service role), or "controller". */
    private RoleModel role(RealmModel realm, String key) {
        if (TeamAccess.CONTROLLER.equals(key)) {
            return realm.getRole(TeamAccess.CONTROLLER);
        }
        int slash = key == null ? -1 : key.indexOf('/');
        if (slash < 0 || !domains(realm).contains(key.substring(0, slash))) {
            return null;
        }
        ClientModel client = TeamAccess.clientOf(session, realm, key.substring(0, slash));
        return client == null ? null : client.getRole(key.substring(slash + 1));
    }

    private boolean isController(RealmModel realm, UserModel user) {
        RoleModel role = realm.getRole(TeamAccess.CONTROLLER);
        return role != null && user.hasRole(role);
    }

    /** var.team_registrant, or whoever registered the domain's client: they hold no service roles. */
    private boolean isRegistrant(RealmModel realm, UserModel user) {
        String email = user.getEmail();
        if (email == null || isController(realm, user)) {
            return false;
        }
        return email.equalsIgnoreCase(realm.getAttribute(TeamAccess.REGISTRANT))
                || domains(realm).stream().map(d -> TeamAccess.clientOf(session, realm, d))
                        .anyMatch(c -> c != null && email.equalsIgnoreCase(c.getAttribute(EMAIL)));
    }

    private void history(RealmModel realm, UserModel me, UserModel user, OperationType operation, String what) {
        EventStoreProvider store = session.getProvider(EventStoreProvider.class);
        if (store == null) {
            return;
        }
        AdminEvent event = new AdminEvent();
        event.setId(KeycloakModelUtils.generateId());
        event.setTime(System.currentTimeMillis());
        event.setRealmId(realm.getId());
        event.setRealmName(realm.getName());
        event.setOperationType(operation);
        event.setResourceType(ResourceType.USER);
        event.setResourcePath("users/" + user.getId());
        AuthDetails details = new AuthDetails();
        details.setRealmId(realm.getId());
        details.setUserId(me.getId());
        details.setIpAddress(session.getContext().getConnection().getRemoteAddr());
        event.setAuthDetails(details);
        try {
            event.setRepresentation(JsonSerialization.writeValueAsString(Map.of("access", what, "by", String.valueOf(me.getEmail()))));
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
        store.onEvent(event, true);
    }

    private List<Map<String, String>> history(RealmModel realm, UserModel user) {
        EventStoreProvider store = session.getProvider(EventStoreProvider.class);
        if (store == null) {
            return List.of();
        }
        return store.createAdminQuery().realm(realm.getId()).resourcePath("users/" + user.getId() + "*")
                .orderByDescTime().maxResults(HISTORY).getResultStream()
                .map(AccessPage::line).toList();
    }

    /** One history line: this page's words, or what the admin API did (the console, the scripts). */
    private static Map<String, String> line(AdminEvent event) {
        String by = "an admin";
        String what = event.getOperationType().name().toLowerCase(Locale.ROOT) + " "
                + (event.getResourcePath() == null ? "" : event.getResourcePath().replaceAll("^users/[^/]*/?", ""));
        try {
            Object value = event.getRepresentation() == null ? null : JsonSerialization.readValue(event.getRepresentation(), Object.class);
            if (value instanceof Map<?, ?> map && map.get("access") != null) {
                what = String.valueOf(map.get("access"));
                by = String.valueOf(map.get("by"));
            } else if (value instanceof List<?> list) {
                String names = String.join(", ", list.stream().filter(Map.class::isInstance)
                        .map(r -> String.valueOf(((Map<?, ?>) r).get("name"))).toList());
                what = (event.getOperationType() == OperationType.DELETE ? "took " + names + " away" : "gave " + names);
            }
        } catch (java.io.IOException e) {
            LOG.debug("access page: an admin event's representation is not JSON", e);
        }
        return Map.of("when", WHEN.format(Instant.ofEpochMilli(event.getTime())), "by", by, "what", what.trim());
    }

    private String csrf(UserSessionModel userSession) {
        String note = userSession.getNote(CSRF_NOTE);
        if (note == null) {
            byte[] bytes = new byte[32];
            RANDOM.nextBytes(bytes);
            note = HexFormat.of().formatHex(bytes);
            userSession.setNote(CSRF_NOTE, note);
        }
        return note;
    }

    private LoginFormsProvider form(RealmModel realm, UserModel user) {
        return session.getProvider(LoginFormsProvider.class)
                .setAttribute("pageUrl", self(realm))
                .setAttribute("signedInAs", String.valueOf(user.getEmail()))
                .setAttribute("signOutUrl", base(realm) + "/protocol/openid-connect/logout?client_id=" + LOGIN_CLIENT);
    }

    private static Response html(int status, LoginFormsProvider form) {
        return Response.fromResponse(form.setStatus(Response.Status.fromStatusCode(status)).createForm("team-access.ftl"))
                .header("Cache-Control", "no-store").build();
    }

    private String base(RealmModel realm) {
        return session.getContext().getUri(UrlType.FRONTEND).getBaseUri() + "realms/" + realm.getName();
    }

    private String self(RealmModel realm) {
        return base(realm) + "/" + AccessPageFactory.PROVIDER_ID;
    }

    private String origin(RealmModel realm) {
        URI uri = session.getContext().getUri(UrlType.FRONTEND).getBaseUri();
        return uri.getScheme() + "://" + uri.getAuthority();
    }

    /** The realm's sign-in, through team-access, back to this page. The code is never redeemed, so the verifier is not kept. */
    private URI signIn(RealmModel realm) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String challenge = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        return org.keycloak.common.util.KeycloakUriBuilder.fromUri(base(realm) + "/protocol/openid-connect/auth")
                .queryParam("client_id", LOGIN_CLIENT).queryParam("response_type", "code").queryParam("scope", "openid")
                .queryParam("redirect_uri", self(realm)).queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256").build();
    }
}
