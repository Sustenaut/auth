package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.email.EmailException;
import org.keycloak.email.freemarker.FreeMarkerEmailTemplateProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;

/**
 * Keycloak's email templates (theme family), sent on behalf of a registered domain: its
 * settings (display name, home page, invitation text, who to ask; AppRegistrationResource's
 * /settings) go into the template as tenantName, tenantHome, tenantIntro and tenantHelp, and
 * its display name becomes the sender's name. The sender's address stays the realm's own
 * (one mailbox for the whole service). Without a domain the realm's neutral wording is used.
 */
class TenantEmail extends FreeMarkerEmailTemplateProvider {

    private final ClientModel tenant;

    TenantEmail(KeycloakSession session, ClientModel tenant) {
        super(session);
        this.tenant = tenant;
        setRealm(session.getContext().getRealm());
        tenantAttributes(tenant).forEach(this::setAttribute);
    }

    /** The template variables of a domain's settings; empty for none. */
    static Map<String, Object> tenantAttributes(ClientModel client) {
        Map<String, Object> out = new HashMap<>();
        if (client == null) {
            return out;
        }
        put(out, "tenantName", client.getAttribute(TENANT_NAME));
        put(out, "tenantHome", client.getAttribute(TENANT_HOME));
        put(out, "tenantIntro", client.getAttribute(TENANT_INTRO));
        put(out, "tenantHelp", client.getAttribute(TENANT_HELP));
        return out;
    }

    private static void put(Map<String, Object> out, String key, String value) {
        if (value != null && !value.isBlank()) {
            out.put(key, value);
        }
    }

    /** The invitation: the passkey setup link, in the domain's words when it has settings. */
    void sendInvitation(String link, long expirationInMinutes) throws EmailException {
        Map<String, Object> body = new HashMap<>(attributes);
        addLinkInfoIntoAttributes(link, expirationInMinutes, body);
        String name = tenantName();
        if (name == null) {
            send("executeActionsSubject", "executeActions.ftl", body);
        } else {
            send("familyInviteSubject", List.of(name), "executeActions.ftl", body);
        }
    }

    /** Any template, with the domain's settings added to its variables. */
    void sendTenant(String subjectKey, List<Object> subjectArguments, String template, Map<String, Object> body)
            throws EmailException {
        Map<String, Object> all = new HashMap<>(attributes);
        all.putAll(body);
        send(subjectKey, subjectArguments, template, all);
    }

    String tenantName() {
        String name = tenant == null ? null : tenant.getAttribute(TENANT_NAME);
        return name == null || name.isBlank() ? null : name;
    }

    @Override
    protected void send(Map<String, String> config, String subject, String textBody, String htmlBody, String address)
            throws EmailException {
        String name = tenantName();
        if (name != null) {
            config = new HashMap<>(config);
            config.put("fromDisplayName", name);
        }
        super.send(config, subject, textBody, htmlBody, address);
    }
}
