package eu.sustenaut.auth;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;
import org.xbill.DNS.dnssec.ValidatingResolver;

/**
 * A domain registering for sign-in with this realm, approved by its DNS, the way ACME's dns-01
 * challenge works (AppRegistrationResource, AppRegistrationResourceFactory, FamilyClientRules).
 * One registration, one client, per domain; which services on the domain use it is the domain
 * owner's business.
 *
 * <ol>
 *   <li>The registrant signs in to this realm (the device flow of the client app-registration:
 *       a passkey or an emailed code) with a verified email address exactly at the domain, and
 *       asks: the domain (one of the realm's allowed domains) and the redirect URIs (https, any
 *       host on or under the domain). Keycloak answers with the record to publish,
 *       {@code _sustenaut-auth.<domain> TXT "sa1=<token>"}, and keeps the request, as a disabled
 *       client, for 7 days.
 *   <li>Whoever runs the domain's DNS publishes the record: that is the approval.
 *   <li>Verify (the same registrant, signed in): Keycloak looks the record up with DNSSEC
 *       validation ({@link #lookup}; the domain must be signed); once a validated answer has it,
 *       the client (id = the domain) is switched on and its credentials returned, once. A client
 *       the domain had before is revoked.
 *   <li>Every week Keycloak asks again. A definite miss (a validated "no": the record gone or
 *       changed), confirmed by a second one an hour later, revokes the
 *       client: switched off for good, the registrant told a new registration is needed, deleted
 *       after 30 days. Answers that are not definite (no answer, a validation failure) change
 *       nothing and are asked again an hour later.
 * </ol>
 *
 * The sign-in proves who asked; the TXT token, public once in DNS, only proves control of the
 * DNS. Only realms with the attribute {@link #DOMAINS} have any of this. The state is on the
 * clients as attributes (a hash of the token, never the token).
 */
final class AppRegistration {

    private static final Logger LOG = Logger.getLogger(AppRegistration.class);

    // Realm attributes (realm/family.json, realm/team.json).
    static final String DOMAINS = "sustenaut.appRegistration.domains";
    static final String CHECK_SECONDS = "sustenaut.appRegistration.checkSeconds";
    static final String RETRY_SECONDS = "sustenaut.appRegistration.retrySeconds";
    static final String ALERT_EMAIL = "sustenaut.appRegistration.alertEmail";
    static final String DNS_SERVER = "sustenaut.appRegistration.dnsServer";
    static final String TRUST_ANCHORS = "sustenaut.appRegistration.trustAnchors";
    static final String REMOVAL_SECONDS = "sustenaut.appRegistration.removalSeconds";

    // Client attributes.
    static final String STATE = "sustenaut.app.state"; // pending, active, revoked
    static final String DOMAIN = "sustenaut.app.domain";
    static final String EMAIL = "sustenaut.app.registrant";
    static final String REGISTRANT_ID = "sustenaut.app.registrantId";
    static final String TOKEN_HASH = "sustenaut.app.tokenHash";
    static final String EXPIRES = "sustenaut.app.expires";
    static final String NEXT_CHECK = "sustenaut.app.nextCheck";
    static final String MISSES = "sustenaut.app.misses";
    static final String REVOKED = "sustenaut.app.revoked";

    // A domain's settings, on its client (AppRegistrationResource /settings): what its users see.
    static final String TENANT_NAME = "sustenaut.tenant.displayName";
    static final String TENANT_HOME = "sustenaut.tenant.homeUrl";
    static final String TENANT_INTRO = "sustenaut.tenant.inviteIntro";
    static final String TENANT_HELP = "sustenaut.tenant.helpContact";
    static final String TENANT_NOTIFY = "sustenaut.tenant.notifyUrl"; // SignInNotice
    // On users: the domains that invited them (AppRegistrationResource /invite).
    static final String INVITED_BY = "sustenaut.invitedBy";
    /** The domain whose invitation created the account and gave its names (GET people shows them to it only). */
    static final String NAMES_BY = "sustenaut.namesBy";
    /** When the person first signed in (epoch seconds; SignInRecorder). */
    static final String SIGNED_IN = "sustenaut.signedInAt";
    /** When the last domain let the person go and the account was switched off (epoch seconds; FamilyRemoval). */
    static final String REMOVED_AT = "sustenaut.removedAt";

    static final String PENDING_PREFIX = "pending-";
    static final String REVOKED_PREFIX = "revoked-";
    static final String RECORD_PREFIX = "_sustenaut-auth.";
    static final String VALUE_PREFIX = "sa1=";
    static final long PENDING_SECONDS = 7 * 24 * 3600;
    static final long REVOKED_KEEP_SECONDS = 30L * 24 * 3600;
    static final String DEVICE_CLIENT = "app-registration";
    static final long DEFAULT_CHECK_SECONDS = 7 * 24 * 3600;
    static final long DEFAULT_RETRY_SECONDS = 3600;
    static final long DEFAULT_REMOVAL_SECONDS = 24 * 3600;
    static final long DELETE_AFTER_SECONDS = 30L * 24 * 3600;
    static final int MISSES_TO_REVOKE = 2;
    static final int MAX_PENDING = 20;

    static final List<String> SCOPES = List.of("basic", "email", "profile", "web-origins", "acr");

    /** What the domain's DNS says about a client's record. */
    enum Answer { PRESENT, ABSENT, UNKNOWN }

    private AppRegistration() {}

    static Stream<ClientModel> withState(KeycloakSession session, RealmModel realm, String state) {
        return session.clients().getClientsStream(realm).filter(c -> state.equals(c.getAttribute(STATE)));
    }

    static List<String> domains(RealmModel realm) {
        String value = realm.getAttribute(DOMAINS);
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.toLowerCase().split("[,\\s]+")).filter(d -> !d.isEmpty()).toList();
    }

    static long seconds(RealmModel realm, String attribute, long fallback) {
        try {
            return Long.parseLong(realm.getAttribute(attribute).trim());
        } catch (RuntimeException e) {
            return fallback;
        }
    }

    static String recordName(String domain) {
        return RECORD_PREFIX + domain;
    }

    /** The host of a plain https URL (no port, user, fragment or wildcard) on the domain or under it. */
    static String hostOf(String url, String domain) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (Exception e) {
            throw new IllegalArgumentException("not a URL: " + url);
        }
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
        if (!"https".equals(uri.getScheme()) || uri.getUserInfo() != null || uri.getPort() != -1
                || uri.getFragment() != null || url.contains("*") || !host.matches("[a-z0-9.-]+")) {
            throw new IllegalArgumentException("only plain https URLs without wildcards: " + url);
        }
        if (!under(host, domain)) {
            throw new IllegalArgumentException("host not under " + domain + ": " + host);
        }
        return host;
    }

    static boolean under(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain);
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static boolean matches(String hash, String value) {
        return hash != null && value != null && MessageDigest.isEqual(
                hash.getBytes(StandardCharsets.US_ASCII), sha256(value).getBytes(StandardCharsets.US_ASCII));
    }

    /** The answer, and in words why (for verify's reply and the log). */
    record Result(Answer answer, String why) {}

    /**
     * What the domain's DNS says about the client's record, DNSSEC-validated from the trust
     * anchors (IANA's root keys, or the realm's trustAnchors): PRESENT if the validated answer
     * has the token; ABSENT only for a validated "no" (no such name, no TXT, or no TXT value with
     * this token); UNKNOWN for anything else: no answer, a bogus one, or one that cannot be
     * validated (an unsigned domain). UNKNOWN never revokes anything and never issues a client.
     */
    static Result lookup(RealmModel realm, ClientModel client) {
        String name = recordName(client.getAttribute(DOMAIN));
        try {
            Resolver validating = validating(realm.getAttribute(DNS_SERVER), realm.getAttribute(TRUST_ANCHORS));
            Message txt = ask(validating, name, Type.TXT, true);
            Answer answer = validated(txt, client.getAttribute(TOKEN_HASH));
            return new Result(answer, switch (answer) {
                case PRESENT -> "validated record present";
                case ABSENT -> "validated: " + name + " has no TXT value with this token";
                case UNKNOWN -> "the answer for " + name + " did not validate with DNSSEC (" + Rcode.string(txt.getRcode())
                        + (txt.getHeader().getFlag(Flags.AD) ? "" : ", not authenticated") + "); is the domain signed?";
            });
        } catch (IOException e) {
            return new Result(Answer.UNKNOWN, "could not look up " + name + ": " + e.getMessage());
        }
    }

    /** From the validating resolver's answer to the TXT question. */
    static Answer validated(Message txt, String hash) {
        if (!txt.getHeader().getFlag(Flags.AD)) {
            return Answer.UNKNOWN;
        }
        if (txt.getRcode() == Rcode.NXDOMAIN) {
            return Answer.ABSENT;
        }
        if (txt.getRcode() != Rcode.NOERROR) {
            return Answer.UNKNOWN;
        }
        for (Record r : txt.getSection(Section.ANSWER)) {
            if (r instanceof TXTRecord record) {
                String v = String.join("", record.getStrings()).trim();
                if (v.startsWith(VALUE_PREFIX) && matches(hash, v.substring(VALUE_PREFIX.length()).trim())) {
                    return Answer.PRESENT;
                }
            }
        }
        return Answer.ABSENT;
    }

    /**
     * A DNSSEC-validating resolver on top of the given resolver (host[:port]; empty for the
     * system's), with the given trust anchors (DS or DNSKEY records in zone-file form, several
     * separated by newlines or "|"; empty for IANA's root keys).
     */
    static Resolver validating(String server, String anchors) throws IOException {
        ValidatingResolver validating = new ValidatingResolver(resolver(server));
        String text = anchors == null || anchors.isBlank() ? ROOT_ANCHORS : anchors.replace("|", "\n");
        validating.loadTrustAnchors(new ByteArrayInputStream(text.getBytes(StandardCharsets.US_ASCII)));
        return validating;
    }

    /** The root zone's key-signing keys (data.iana.org/root-anchors): KSK-2017 and KSK-2024. */
    static final String ROOT_ANCHORS = """
            . IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
            . IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
            """;

    static Resolver resolver(String server) throws IOException {
        if (server == null || server.isBlank()) {
            return new ExtendedResolver();
        }
        String[] hostPort = server.trim().split(":");
        SimpleResolver resolver = new SimpleResolver(new InetSocketAddress(
                InetAddress.getByName(hostPort[0]), hostPort.length > 1 ? Integer.parseInt(hostPort[1]) : 53));
        resolver.setTimeout(Duration.ofSeconds(5));
        return resolver;
    }

    /** One query, no cache; recursion desired only when asking a resolver. */
    static Message ask(Resolver resolver, String name, int type, boolean recursive) throws IOException {
        Message query = Message.newQuery(Record.newRecord(Name.fromString(name.endsWith(".") ? name : name + "."), type, DClass.IN));
        if (!recursive) {
            query.getHeader().unsetFlag(Flags.RD);
        }
        return resolver.send(query);
    }

    /** The address people know this service by, for emails (KC_HOSTNAME, else auth.sustenaut.eu). */
    static String serviceName() {
        String hostname = System.getenv("KC_HOSTNAME");
        if (hostname == null || hostname.isBlank()) {
            return "auth.sustenaut.eu";
        }
        return hostname.replaceFirst("^https?://", "").replaceAll("/.*$", "");
    }

    static boolean mail(KeycloakSession session, RealmModel realm, String to, String subject, String text) {
        if (to == null || to.isBlank() || realm.getSmtpConfig() == null || realm.getSmtpConfig().isEmpty()) {
            LOG.warnf("app registration: no address or SMTP in realm %s; not emailed: %s", realm.getName(), subject);
            return false;
        }
        try {
            session.getProvider(EmailSenderProvider.class).send(realm.getSmtpConfig(), to.trim(), subject, text, null);
            return true;
        } catch (EmailException e) {
            LOG.warnf(e, "app registration: could not email %s", to);
            return false;
        }
    }

    /**
     * Revokes a domain's client: switched off for good, renamed out of the way of the next
     * registration, kept (with its attributes) for the record. The registrant is told why, and
     * the realm's alert address gets a copy.
     */
    static void revoke(KeycloakSession session, RealmModel realm, ClientModel client, long now, String why) {
        String domain = client.getAttribute(DOMAIN);
        client.setEnabled(false);
        client.setAttribute(STATE, "revoked");
        client.setAttribute(REVOKED, now + " " + why);
        client.setClientId(REVOKED_PREFIX + domain + "-" + now);
        client.setRegistrationToken(null);
        LOG.warnf("app registration: the client of %s is revoked: %s", domain, why);
        String text = why + "\n\nA new registration is required to continue authenticating with "
                + serviceName() + ". Sign-in for " + domain + " through " + serviceName() + " has stopped.";
        String subject = "Sign-in for " + domain + " through " + serviceName() + " is revoked";
        mail(session, realm, client.getAttribute(EMAIL), subject, text);
        String alert = realm.getAttribute(ALERT_EMAIL);
        if (alert != null && !alert.isBlank() && !alert.equalsIgnoreCase(client.getAttribute(EMAIL))) {
            mail(session, realm, alert, subject, "Sent to the registrant, " + client.getAttribute(EMAIL) + ":\n\n" + text);
        }
    }
}
