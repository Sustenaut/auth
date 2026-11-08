package eu.sustenaut.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;
import org.keycloak.authentication.actiontoken.DefaultActionToken;

/**
 * The "Sign me in" link of the family sign-in email ({@link FamilySignInForm}): the account, the
 * authentication session it was asked for (asid), the client, and the random secret whose hash
 * that session keeps. Signed by the realm; expires with the code.
 */
public class FamilyLinkToken extends DefaultActionToken {

    public static final String TOKEN_TYPE = "family-sign-in-link";

    @JsonProperty("fls")
    private String secret;

    public FamilyLinkToken(String userId, int expires, UUID nonce, String compoundAuthSessionId, String clientId,
            String secret) {
        super(userId, TOKEN_TYPE, expires, nonce, compoundAuthSessionId);
        this.issuedFor = clientId;
        this.secret = secret;
    }

    private FamilyLinkToken() {}

    public String getSecret() {
        return secret;
    }
}
