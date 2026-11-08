package eu.sustenaut.auth;

import static eu.sustenaut.auth.AppRegistration.*;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

/**
 * Tells the domains that invited someone of their first sign-in (SignInRecorder): a POST to each
 * one's notify_url (its settings), so it can act at once (example.net finishes an email change).
 *
 * <pre>
 * POST &lt;notify_url&gt;
 * Content-Type: application/json
 * X-Sustenaut-Timestamp: 1793180000                         (Unix seconds, when it was sent)
 * X-Sustenaut-Signature: sha256=&lt;hex HMAC-SHA256(client secret, timestamp + "." + body)&gt;
 *
 * {"event": "first_sign_in", "domain": "example.net", "email": "anna@example.org", "at": "2026-10-28T12:00:00Z"}
 * </pre>
 *
 * The key is the domain's client secret, which only it and auth.sustenaut.eu hold. A receiver
 * checks the signature over the exact body bytes, refuses a timestamp more than
 * {@link #REPLAY_SECONDS} from its own clock, and refuses a signature it has already seen
 * within that window (a replay).
 *
 * <p>Sent only after the sign-in has committed, from a small pool of its own, with short
 * timeouts and no retry: a sign-in never waits on a domain, and a domain that is down misses
 * the notice (it should also look for itself now and then, with GET people). Only to domains
 * that invited the person (sustenaut.invitedBy), with an active client and a notify_url.
 */
final class SignInNotice {

    private static final Logger LOG = Logger.getLogger(SignInNotice.class);

    /** How far a notice's timestamp may be from the receiver's clock; it should refuse anything else. */
    static final long REPLAY_SECONDS = 300;
    static final int CONNECT_MS = 3000, READ_MS = 5000;

    /** Two senders; at most 100 notices waiting, more are dropped (and logged). */
    private static final ThreadPoolExecutor SENDERS = new ThreadPoolExecutor(2, 2, 60, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(100), runnable -> {
                Thread t = new Thread(runnable, "sustenaut-sign-in-notice");
                t.setDaemon(true);
                return t;
            }, (runnable, pool) -> LOG.warn("sign-in notice: too many waiting; one dropped"));

    private SignInNotice() {}

    record Notice(String domain, String url, String secret) {}

    /** The notices for user's first sign-in, sent once the current transaction has committed. */
    static void afterCommit(KeycloakSession session, RealmModel realm, UserModel user, long at) {
        List<Notice> notices = new ArrayList<>();
        user.getAttributeStream(INVITED_BY).distinct().forEach(domain -> {
            ClientModel client = session.clients().getClientByClientId(realm, domain);
            String url = client == null ? null : client.getAttribute(TENANT_NOTIFY);
            if (url != null && client.isEnabled() && "active".equals(client.getAttribute(STATE)) && client.getSecret() != null) {
                notices.add(new Notice(domain, url, client.getSecret()));
            }
        });
        if (notices.isEmpty() || user.getEmail() == null) {
            return;
        }
        CloseableHttpClient http = session.getProvider(HttpClientProvider.class).getHttpClient();
        String email = user.getEmail();
        session.getTransactionManager().enlistAfterCompletion(new AbstractKeycloakTransaction() {
            @Override
            protected void commitImpl() {
                for (Notice notice : notices) {
                    SENDERS.execute(() -> send(http, notice, email, at));
                }
            }

            @Override
            protected void rollbackImpl() {}
        });
    }

    static String body(String domain, String email, long at) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("event", "first_sign_in");
        out.put("domain", domain);
        out.put("email", email);
        out.put("at", Instant.ofEpochSecond(at).toString());
        try {
            return JsonSerialization.writeValueAsString(out);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** "sha256=" + hex HMAC-SHA256(secret, timestamp + "." + body). */
    static String sign(String secret, long timestamp, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal((timestamp + "." + body).getBytes(StandardCharsets.UTF_8));
            return "sha256=" + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void send(CloseableHttpClient http, Notice notice, String email, long at) {
        String body = body(notice.domain(), email, at);
        long now = Instant.now().getEpochSecond();
        HttpPost post = new HttpPost(notice.url());
        post.setConfig(RequestConfig.custom().setConnectTimeout(CONNECT_MS).setConnectionRequestTimeout(CONNECT_MS)
                .setSocketTimeout(READ_MS).setRedirectsEnabled(false).build());
        post.setHeader("X-Sustenaut-Timestamp", Long.toString(now));
        post.setHeader("X-Sustenaut-Signature", sign(notice.secret(), now, body));
        post.setEntity(new StringEntity(body, ContentType.APPLICATION_JSON));
        try (CloseableHttpResponse response = http.execute(post)) {
            int status = response.getStatusLine().getStatusCode();
            if (status / 100 == 2) {
                LOG.debugf("sign-in notice: %s took it (%d)", notice.domain(), status);
            } else {
                LOG.warnf("sign-in notice: %s answered %d", notice.domain(), status);
            }
        } catch (Exception e) {
            LOG.warnf("sign-in notice: %s not reached (%s)", notice.domain(), e.toString());
        }
    }
}
