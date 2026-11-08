package eu.sustenaut.auth;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/** The invite-only realms' sign-in step (family, team): an emailed link and code, or a passkey ({@link FamilySignInForm}). */
public class FamilySignInFormFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "family-sign-in";

    @Override
    public Authenticator create(KeycloakSession session) {
        return new FamilySignInForm(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Invite-only sign-in: emailed link and code, or passkey";
    }

    @Override
    public String getHelpText() {
        return "An email field; a one-time sign-in link and code sent to that address, or a passkey offered in the field. Never a password, never creates an account.";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return new Requirement[] {Requirement.REQUIRED, Requirement.ALTERNATIVE};
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
