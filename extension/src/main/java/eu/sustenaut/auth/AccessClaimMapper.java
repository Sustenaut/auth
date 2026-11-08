package eu.sustenaut.auth;

import java.util.List;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

/**
 * The claim "access" in a domain's tokens (TeamAccess): the person's roles on THAT client only. A
 * controller gets all of the client's roles and the word "controller". An empty list for someone
 * with none. Works with oauth2-proxy's --oidc-groups-claim=access --allowed-group=&lt;role&gt;, which
 * passes them on in X-Forwarded-Groups. Worked out afresh at each token, so a change shows at the
 * person's next sign-in or token refresh.
 */
public class AccessClaimMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "sustenaut-access";
    static final String CLAIM = "access";

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mapping, UserSessionModel userSession,
            KeycloakSession session, ClientSessionContext context) {
        token.getOtherClaims().put(CLAIM, TeamAccess.claimOf(context.getClientSession().getClient(), userSession.getUser()));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Sustenaut access claim";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "The person's roles on this client in the claim access (a controller: all of them, and controller).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
