package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.keycloak.services.clientregistration.policy.AbstractClientRegistrationPolicyFactory;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;

/**
 * Keycloak's own client registration endpoints in a realm with app registration: new clients
 * only through /app-registration and its DNS record (AppRegistration), never here. An app that
 * has its client may read it and change it with its registration access token, within the same
 * limits it was given: same client id, every URL on a host under its domain, confidential, code flow
 * with PKCE (S256), the openid/email/profile scopes, no protocol mappers (but the access claim's,
 * in a realm with service roles: TeamAccess), no service account, no other grant, no full scope. It cannot switch itself on, or touch the DNS-approval state.
 */
public class FamilyClientRules extends AbstractClientRegistrationPolicyFactory implements ClientRegistrationPolicy {

    public static final String PROVIDER_ID = "family-client-rules";

    static final Set<String> FORBIDDEN_TRUE_ATTRIBUTES = Set.of(
            "oauth2.device.authorization.grant.enabled", "oidc.ciba.grant.enabled",
            "standard.token.exchange.enabled", "oauth2.jwt.authorization.grant.enabled");

    @Override
    public void beforeRegister(ClientRegistrationContext context) throws ClientRegistrationPolicyException {
        throw new ClientRegistrationPolicyException("register through /app-registration (approval by a DNS record)");
    }

    @Override
    public void afterRegister(ClientRegistrationContext context, ClientModel client) {}

    @Override
    public void beforeUpdate(ClientRegistrationContext context, ClientModel client) throws ClientRegistrationPolicyException {
        require("active".equals(client.getAttribute(STATE)), "only active DNS-approved clients can be changed here");
        check(context.getClient(), client);
    }

    @Override
    public void afterUpdate(ClientRegistrationContext context, ClientModel client) {
        client.setFullScopeAllowed(false);
        if (TeamAccess.enabled(client.getRealm())) {
            TeamAccess.ensureMapper(client);
        }
    }

    @Override
    public void beforeView(ClientRegistrationProvider provider, ClientModel client) {}

    @Override
    public void beforeDelete(ClientRegistrationProvider provider, ClientModel client) {}

    static void check(ClientRepresentation c, ClientModel current) throws ClientRegistrationPolicyException {
        require(Objects.equals(c.getClientId(), current.getClientId()), "the client id cannot change");
        require(c.isEnabled() == null || c.isEnabled() == current.isEnabled(), "an app cannot switch its client on or off");
        require(c.getProtocol() == null || "openid-connect".equals(c.getProtocol()), "protocol must be openid-connect");
        require(!Boolean.TRUE.equals(c.isPublicClient()), "the client must be confidential");
        require(!Boolean.TRUE.equals(c.isBearerOnly()), "bearer-only clients are not allowed");
        require(c.getClientAuthenticatorType() == null || "client-secret".equals(c.getClientAuthenticatorType()),
                "client authentication must be client-secret");
        require(!Boolean.FALSE.equals(c.isStandardFlowEnabled()), "the authorization code flow must be on");
        require(!Boolean.TRUE.equals(c.isImplicitFlowEnabled()), "the implicit flow is not allowed");
        require(!Boolean.TRUE.equals(c.isDirectAccessGrantsEnabled()), "password grants are not allowed");
        require(!Boolean.TRUE.equals(c.isServiceAccountsEnabled()), "service accounts are not allowed");
        require(!Boolean.TRUE.equals(c.getAuthorizationServicesEnabled()), "authorization services are not allowed");
        require(!Boolean.TRUE.equals(c.isFullScopeAllowed()), "full scope is not allowed");
        boolean accessClaim = current.getRealm() != null && TeamAccess.enabled(current.getRealm());
        require(c.getProtocolMappers() == null || c.getProtocolMappers().stream()
                .allMatch(m -> accessClaim && AccessClaimMapper.PROVIDER_ID.equals(m.getProtocolMapper())),
                "protocol mappers are not allowed");

        Map<String, String> attributes = c.getAttributes() == null ? Map.of() : c.getAttributes();
        require(attributes.isEmpty() || "S256".equals(attributes.get("pkce.code.challenge.method")),
                "PKCE (S256) is required");
        for (String name : FORBIDDEN_TRUE_ATTRIBUTES) {
            require(!"true".equals(attributes.get(name)), name + " is not allowed");
        }
        for (Map.Entry<String, String> a : attributes.entrySet()) {
            if (a.getKey().startsWith("sustenaut.")) {
                require(Objects.equals(a.getValue(), current.getAttribute(a.getKey())), a.getKey() + " cannot change");
            }
        }
        if (c.getDefaultClientScopes() != null) {
            require(SCOPES.containsAll(c.getDefaultClientScopes()) && c.getDefaultClientScopes().contains("email"),
                    "default client scopes must include email and be among " + SCOPES);
        }
        require(c.getOptionalClientScopes() == null || c.getOptionalClientScopes().isEmpty(),
                "optional client scopes are not allowed");

        String domain = current.getAttribute(DOMAIN);
        List<String> urls = new ArrayList<>();
        if (c.getRedirectUris() != null) urls.addAll(c.getRedirectUris());
        String logout = attributes.get("post.logout.redirect.uris");
        if (logout != null && !logout.isBlank()) urls.addAll(List.of(logout.split("##")));
        for (String url : new String[] {c.getRootUrl(), c.getBaseUrl(), c.getAdminUrl()}) {
            if (url != null && !url.isEmpty()) urls.add(url);
        }
        if (c.getWebOrigins() != null) {
            c.getWebOrigins().stream().filter(o -> !"+".equals(o)).forEach(urls::add);
        }
        for (String url : urls) {
            try {
                hostOf(url, domain);
            } catch (IllegalArgumentException e) {
                throw new ClientRegistrationPolicyException("URL not allowed: " + e.getMessage());
            }
        }
    }

    private static void require(boolean ok, String message) throws ClientRegistrationPolicyException {
        if (!ok) {
            throw new ClientRegistrationPolicyException(message);
        }
    }

    @Override
    public ClientRegistrationPolicy create(KeycloakSession session, ComponentModel model) {
        return this;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "No registration here (use /app-registration); updates by DNS-approved apps stay within their limits and host.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }
}
