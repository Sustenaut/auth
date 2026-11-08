package eu.sustenaut.auth;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Serves /realms/&lt;realm&gt;/access (AccessPage). */
public class AccessPageFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "access";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new AccessPage(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
