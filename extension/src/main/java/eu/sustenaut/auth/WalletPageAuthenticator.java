package eu.sustenaut.auth;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Shows the login page and nothing else. The page (theme sustenaut, login.ftl) offers only
 * the wallet; the wallet plugin finishes the sign-in through its own endpoint. Anything posted
 * back to this step, such as a username and password, is ignored and the page shown again, so
 * the browser flow has no password step at all.
 */
public class WalletPageAuthenticator implements Authenticator, AuthenticatorFactory {

    public static final String PROVIDER_ID = "sustenaut-wallet-page";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(context.form().createLoginUsernamePassword());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.challenge(context.form().createLoginUsernamePassword());
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Sustenaut wallet login page";
    }

    @Override
    public String getHelpText() {
        return "Shows the wallet-only login page; never accepts a password.";
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
