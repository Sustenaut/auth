package eu.sustenaut.auth;

import java.io.IOException;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Time;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserVerifiableCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oid4vc.issuance.requiredactions.VerifiableCredentialOfferAction;
import org.keycloak.representations.idm.oid4vc.VerifiableCredentialOfferActionConfig;

/**
 * After every sign-in with a PID (the first one, or one from a new or reset wallet), offers the
 * person a "Sustenaut member" credential for their wallet: Keycloak's own OpenID4VCI offer page,
 * with a pre-authorized code. The credential carries the account's id (sub) and is bound to a key
 * the wallet makes; later sign-ins present it instead of the PID.
 *
 * <p>Which wallet profile the sign-in used comes from the wallet plugin (plugin-patches/0002),
 * as the auth note {@value #PROFILE_NOTE}. Offering is per sign-in, not stored on the account:
 * skipping it simply means being offered again at the next PID sign-in.
 */
public class MemberCredentialAction implements RequiredActionProvider, RequiredActionFactory {

    public static final String PROVIDER_ID = "sustenaut-member-credential";
    /** Set by plugin-patches/0002 on the login's authentication session. */
    public static final String PROFILE_NOTE = "oid4vp.profile_id";
    public static final String PID_PROFILE = "eu-pid";
    public static final String CREDENTIAL_CONFIGURATION_ID = "sustenaut-member";
    public static final String WALLET_CLIENT_ID = "sustenaut-wallet";

    private final VerifiableCredentialOfferAction offer = new VerifiableCredentialOfferAction();

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        if (PID_PROFILE.equals(context.getAuthenticationSession().getAuthNote(PROFILE_NOTE))) {
            context.getAuthenticationSession().addRequiredAction(PROVIDER_ID);
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        grant(context);
        VerifiableCredentialOfferActionConfig config = new VerifiableCredentialOfferActionConfig();
        config.setCredentialConfigurationId(CREDENTIAL_CONFIGURATION_ID);
        config.setClientId(WALLET_CLIENT_ID);
        config.setPreAuthorized(true);
        try {
            context.getAuthenticationSession().setClientNote(Constants.KC_ACTION_PARAMETER, config.asEncodedParameter());
        } catch (IOException e) {
            throw new IllegalStateException("Could not encode the credential offer", e);
        }
        // Keycloak's offer page: QR code and same-device link, then Continue (or Cancel, to skip).
        offer.requiredActionChallenge(context);
    }

    /** Keycloak issues a credential type only to users granted it; every account gets this one. */
    private static void grant(RequiredActionContext context) {
        ClientScopeModel scope = KeycloakModelUtils.getClientScopeByName(context.getRealm(), CREDENTIAL_CONFIGURATION_ID);
        if (scope == null) {
            throw new IllegalStateException("Client scope " + CREDENTIAL_CONFIGURATION_ID + " is missing");
        }
        String userId = context.getUser().getId();
        if (context.getSession().users().getVerifiableCredentialByClientScope(userId, scope.getId()) == null) {
            UserVerifiableCredentialModel granted = new UserVerifiableCredentialModel(null, scope.getId());
            granted.setCreatedDate(Time.currentTimeMillis());
            context.getSession().users().addVerifiableCredential(userId, granted);
        }
    }

    @Override
    public void processAction(RequiredActionContext context) {
        context.getAuthenticationSession().removeClientNote(Constants.KC_ACTION_PARAMETER);
        context.getAuthenticationSession().removeAuthNote(PROFILE_NOTE);
        context.success();
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "Sustenaut member credential";
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
