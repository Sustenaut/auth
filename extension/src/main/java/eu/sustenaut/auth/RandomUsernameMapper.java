package eu.sustenaut.auth;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Gives an account imported from a wallet a random username such as {@code u-3f9a1c0b7e2d},
 * replacing the one the wallet plugin derives from the PID's identifier, so the national
 * identifier never shows as a username, in the admin console or in tokens. The federated
 * link's display name gets the same value; the link id itself is already a hash.
 */
public class RandomUsernameMapper extends AbstractIdentityProviderMapper {

    public static final String PROVIDER_ID = "sustenaut-random-username";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return new String[] {ANY_PROVIDER};
    }

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return true;
    }

    @Override
    public String getDisplayCategory() {
        return "Username";
    }

    @Override
    public String getDisplayType() {
        return "Sustenaut random username";
    }

    @Override
    public String getHelpText() {
        return "Replaces the username of a newly imported account with a random one.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public void importNewUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        String username = randomUsername(session, realm);
        user.setUsername(username);

        String alias = mapperModel.getIdentityProviderAlias();
        FederatedIdentityModel link = session.users().getFederatedIdentity(realm, user, alias);
        if (link != null) {
            session.users()
                    .updateFederatedIdentity(
                            realm, user, new FederatedIdentityModel(alias, link.getUserId(), username, link.getToken()));
        }
    }

    static String randomUsername(KeycloakSession session, RealmModel realm) {
        while (true) {
            byte[] bytes = new byte[6];
            RANDOM.nextBytes(bytes);
            String candidate = "u-" + HexFormat.of().formatHex(bytes);
            if (session.users().getUserByUsername(realm, candidate) == null) {
                return candidate;
            }
        }
    }
}
