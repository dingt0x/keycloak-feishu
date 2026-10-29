package com.keycloak.feishu;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.HashMap;
import java.util.Map;

/**
 * Feishu (Lark) Identity Provider.
 *
 * Implements the OAuth2 authorization-code flow against Feishu Open Platform,
 * retrieves the user info via the Feishu authentication API, and parses all
 * returned fields into Keycloak user attributes.
 *
 * <h3>Endpoints (configurable via {@link FeishuIdentityProviderConfig})</h3>
 * <ul>
 *   <li>Authorize:  defaults to {@code https://accounts.feishu.cn/open-apis/authen/v1/authorize}</li>
 *   <li>Token:      defaults to {@code https://accounts.feishu.cn/oauth/v3/token}</li>
 *   <li>User Info:  defaults to {@code https://open.feishu.cn/open-apis/authen/v1/user_info}</li>
 * </ul>
 */
public class FeishuIdentityProvider extends AbstractOAuth2IdentityProvider<FeishuIdentityProviderConfig>
        implements SocialIdentityProvider<FeishuIdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(FeishuIdentityProvider.class);

    // ---- Feishu user_info response fields ----
    private static final String FLD_SUB = "sub";
    private static final String FLD_NAME = "name";
    private static final String FLD_NICKNAME = "nickname";
    private static final String FLD_EMAIL = "email";
    private static final String FLD_MOBILE = "mobile";
    private static final String FLD_OPEN_ID = "open_id";
    private static final String FLD_UNION_ID = "union_id";
    private static final String FLD_TENANT_KEY = "tenant_key";
    private static final String FLD_AVATAR_URL = "avatar_url";
    private static final String FLD_AVATAR_THUMB = "avatar_thumb";
    private static final String FLD_AVATAR_MIDDLE = "avatar_middle";
    private static final String FLD_AVATAR_BIG = "avatar_big";
    private static final String FLD_USER_ID = "user_id";

    private static final String PROP_FEISHU_USER_INFO = "feishuUserInfo";
    private static final ObjectMapper mapper = new ObjectMapper();

    public FeishuIdentityProvider(KeycloakSession session, FeishuIdentityProviderConfig config) {
        super(session, config);
    }

    // ========================================================================
    // AbstractOAuth2IdentityProvider overrides
    // ========================================================================

    @Override
    protected String getDefaultScopes() {
        return getConfig().getDefaultScope();
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    /**
     * Build the authorization URL with Feishu-specific parameters.
     *
     * Feishu uses the standard OAuth2 {@code client_id} as the
     * application identifier parameter.
     */
    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        FeishuIdentityProviderConfig config = getConfig();
        String authUrl = config.getFeishuAuthUrl();

        UriBuilder uriBuilder = UriBuilder.fromUri(authUrl)
                .queryParam("client_id", config.getClientId())
                .queryParam("redirect_uri", request.getRedirectUri())
                .queryParam("response_type", "code");

        // Add state from the authentication request
        if (request.getState() != null) {
            uriBuilder.queryParam("state", request.getState().getEncoded());
        }

        String prompt = config.getPrompt();
        if (prompt != null && !prompt.isEmpty()) {
            uriBuilder.queryParam("prompt", prompt);
        }

        return uriBuilder;
    }

    // ========================================================================
    // Callback: custom Feishu token exchange
    //
    // Feishu uses a non-standard OAuth2 token exchange:
    //   - Request: JSON POST body with client_id, client_secret, grant_type, code
    //   - Response: {"code":0, "data": {"access_token":"...", ...}}
    //
    // We override the full callback to handle this custom flow.
    // ========================================================================

    @Override
    public Object callback(RealmModel realm, UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                           EventBuilder event) {
        // Must be a subclass of Keycloak's own Endpoint. Quarkus only indexes
        // that class's @GET; a brand-new resource class in this jar is invisible
        // at build time and the broker URL answers 405.
        return new Endpoint(realm, callback, event);
    }

    /**
     * HTTP resource mounted at {@code /broker/{alias}/endpoint}.
     * Inherits {@code @GET} from Keycloak's OAuth endpoint so the Feishu browser redirect is accepted.
     */
    public class Endpoint extends AbstractOAuth2IdentityProvider.Endpoint {
        public Endpoint(RealmModel realm,
                        UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                        EventBuilder event) {
            super(callback, realm, event, FeishuIdentityProvider.this);
        }

        @Override
        public Response authResponse(String state, String code, String error, String errorDescription) {
            if (isBlank(state)) {
                state = getParameter("state");
            }
            if (isBlank(code)) {
                code = getParameter("code");
            }
            if (isBlank(error)) {
                error = getParameter("error");
            }
            if (isBlank(errorDescription)) {
                errorDescription = getParameter("error_description");
            }

            if (!isBlank(error)) {
                logger.errorf("Feishu OAuth2 error received: %s", error);
                if (!isBlank(errorDescription)) {
                    logger.errorf("Feishu OAuth2 error description: %s", errorDescription);
                }
                return callback.error(getConfig(), "Identity provider login failed: " + error);
            }

            if (isBlank(code)) {
                logger.error("Feishu callback called without authorization code");
                return callback.error(getConfig(), "Missing authorization code");
            }

            if (isBlank(state)) {
                logger.error("Feishu callback called without state parameter");
                return callback.error(getConfig(), "Missing state parameter");
            }

            org.keycloak.sessions.AuthenticationSessionModel authSession =
                    callback.getAndVerifyAuthenticationSession(state);
            if (authSession == null) {
                logger.errorf("Failed to verify authentication session for state: %s", state);
                return callback.error(getConfig(), "Invalid state parameter");
            }

            String redirectUri = getConfig().getAlias() != null
                    ? session.getContext().getUri().getBaseUri()
                        + "realms/" + realm.getName()
                        + "/broker/" + getConfig().getAlias() + "/endpoint"
                    : null;
            String accessToken = exchangeCodeForAccessToken(code, redirectUri);
            if (accessToken == null) {
                logger.error("Failed to obtain access token from Feishu");
                return callback.error(getConfig(), "Failed to obtain access token");
            }

            BrokeredIdentityContext identity = doGetFederatedIdentity(accessToken);
            if (identity == null) {
                logger.error("Failed to retrieve federated identity from Feishu");
                return callback.error(getConfig(), "Failed to retrieve user identity");
            }

            identity.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
            identity.setAuthenticationSession(authSession);
            identity.setIdp(FeishuIdentityProvider.this);

            // isStoreToken() returns Boolean and is null when the admin console
            // never touched "Store tokens" — unboxing that NPEs the whole login.
            if (Boolean.TRUE.equals(getConfig().isStoreToken()) && identity.getToken() == null) {
                identity.setToken(accessToken);
            }

            migrateFederatedIdentityLink(realm, identity);

            return callback.authenticated(identity);
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * Read a request parameter from query string or form body.
     */
    private String getParameter(String name) {
        // First try query parameters (GET redirect)
        org.keycloak.http.HttpRequest httpRequest = session.getContext().getHttpRequest();
        if (httpRequest == null) {
            return null;
        }
        // Try query params
        jakarta.ws.rs.core.UriInfo uriInfo = httpRequest.getUri();
        if (uriInfo != null) {
            MultivaluedMap<String, String> queryParams = uriInfo.getQueryParameters();
            if (queryParams != null) {
                String value = queryParams.getFirst(name);
                if (value != null && !value.isEmpty()) {
                    return value;
                }
            }
        }
        // Try form params (POST redirect)
        MultivaluedMap<String, String> formParams = httpRequest.getDecodedFormParameters();
        if (formParams != null) {
            return formParams.getFirst(name);
        }
        return null;
    }

    /**
     * Exchange the authorization code for an access token via Feishu's
     * OAuth2 token endpoint (v3).
     *
     * Feishu expects a JSON POST body with client_id, client_secret,
     * grant_type, code, and redirect_uri. The response is wrapped in a
     * {@code {code, msg, data}} envelope.
     */
    private String exchangeCodeForAccessToken(String code, String redirectUri) {
        FeishuIdentityProviderConfig config = getConfig();

        try {
            Map<String, String> params = new HashMap<>();
            params.put("client_id", config.getClientId());
            params.put("client_secret", config.getClientSecret());
            params.put("grant_type", "authorization_code");
            params.put("code", code);
            params.put("redirect_uri", redirectUri);

            SimpleHttp http = SimpleHttp.doPost(config.getFeishuTokenUrl(), session)
                    .json(params);

            String response = http.asString();
            JsonNode root = mapper.readTree(response);

            if (logger.isDebugEnabled()) {
                int apiCode = root.has("code") ? root.get("code").asInt() : -1;
                String apiMsg = root.has("msg") ? root.get("msg").asText() : "N/A";
                logger.debugf("Feishu token API: code=%d, msg=%s", apiCode, apiMsg);
            }

            // Check for Feishu API-level error
            if (root.has("code") && root.get("code").asInt() != 0) {
                String msg = root.has("msg") ? root.get("msg").asText() : "unknown error";
                logger.errorf("Feishu token API error: code=%d, msg=%s",
                        root.get("code").asInt(), msg);
                throw new IdentityBrokerException("Feishu token API error: " + msg);
            }

            // Unwrap the {code, msg, data} envelope
            if (root.has("data") && root.get("data").has("access_token")) {
                return root.get("data").get("access_token").asText();
            }

            // Fallback: try flat response
            if (root.has("access_token")) {
                return root.get("access_token").asText();
            }

            logger.error("Feishu token response missing access_token");
            throw new IdentityBrokerException("Feishu token response missing access_token");
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Feishu token exchange failed", e);
            throw new IdentityBrokerException("Feishu token exchange failed: " + e.getMessage(), e);
        }
    }

    // ========================================================================
    // Federated identity retrieval
    // ========================================================================

    @Override
    protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken) {
        try {
            JsonNode userInfo = fetchUserInfo(accessToken);
            return buildIdentity(userInfo);
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Feishu user info retrieval failed", e);
            throw new IdentityBrokerException(
                    "Feishu user info retrieval failed: " + e.getMessage(), e);
        }
    }

    /**
     * Call the Feishu user_info API and return the {@code data} payload.
     *
     * Handles both wrapped responses
     * (<code>{"code":0,"msg":"ok","data":{...}}</code>)
     * and flat responses.
     */
    private JsonNode fetchUserInfo(String accessToken) throws Exception {
        SimpleHttp http = SimpleHttp.doGet(getConfig().getFeishuUserInfoUrl(), session)
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json; charset=utf-8");

        String response = http.asString();
        // FEISHU_DEBUG is off unless it is exactly "1" or "true". The body
        // contains names, phones and emails, so any other value stays silent.
        // The token response is never logged: it carries access_token.
        if (isFeishuDebugEnabled(System.getenv("FEISHU_DEBUG"))) {
            logger.infof("Feishu user_info response: %s", response);
        } else {
            logger.debug("Feishu user_info response received (body omitted for security)");
        }

        return unwrapUserInfoResponse(response);
    }

    /**
     * Whether {@code FEISHU_DEBUG} asks for the raw {@code user_info} body.
     *
     * <p>Only {@code 1} and {@code true} (trimmed, case-insensitive) enable it.
     * Missing, blank, and every other value stay off.</p>
     */
    static boolean isFeishuDebugEnabled(String raw) {
        if (raw == null) {
            return false;
        }
        String value = raw.trim();
        return "1".equals(value) || "true".equalsIgnoreCase(value);
    }

    /**
     * Parse a raw Feishu {@code user_info} response body and return the
     * {@code data} payload, unwrapping the {@code {code, msg, data}} envelope.
     *
     * <p>Package-private and static so the envelope handling can be unit
     * tested without a {@link KeycloakSession} or a live HTTP call.</p>
     */
    static JsonNode unwrapUserInfoResponse(String response) throws Exception {
        JsonNode root = mapper.readTree(response);

        // Check for Feishu API-level error
        if (root.has("code") && root.get("code").asInt() != 0) {
            String msg = root.has("msg") ? root.get("msg").asText() : "unknown error";
            logger.errorf("Feishu user_info API error: code=%d, msg=%s",
                    root.get("code").asInt(), msg);
            throw new IdentityBrokerException("Feishu user_info API error: " + msg);
        }

        // Unwrap {code, msg, data} envelope
        if (root.has("data") && root.get("data").isObject()) {
            return root.get("data");
        }

        return root;
    }

    /**
     * Build a {@link BrokeredIdentityContext} from the Feishu user_info
     * response data node.
     */
    BrokeredIdentityContext buildIdentity(JsonNode userInfo) {
        String openId = getField(userInfo, FLD_OPEN_ID);
        String unionId = getField(userInfo, FLD_UNION_ID);
        String sub = getField(userInfo, FLD_SUB);

        // Prefer union_id as the broker user ID; fall back to open_id or sub
        String brokerUserId = unionId;
        if (brokerUserId == null) {
            brokerUserId = openId;
        }
        if (brokerUserId == null) {
            brokerUserId = sub;
        }
        if (brokerUserId == null) {
            throw new IdentityBrokerException(
                    "Feishu user_info does not contain open_id, union_id, or sub");
        }

        BrokeredIdentityContext identity = new BrokeredIdentityContext(
                brokerUserId, getConfig());

        String name = getField(userInfo, FLD_NAME);
        String email = getField(userInfo, FLD_EMAIL);

        identity.setUsername(brokerUserId);
        identity.setFirstName(name);
        // Leave lastName empty. Feishu returns full names only — no separate
        // first/last name fields — so setting it would either duplicate the
        // display name or produce a meaningless split.
        identity.setLastName(null);

        // Only set email if it's non-blank (Feishu may return "")
        if (email != null && !email.isBlank()) {
            identity.setEmail(email);
        }

        // ---- Store raw JSON for attribute mappers ----
        // Store raw JSON for the attribute mapper to process
        identity.getContextData().put(PROP_FEISHU_USER_INFO, userInfo);

        return identity;
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /**
     * Pick the best avatar URL: big > middle > thumb > url.
     */
    static String pickAvatar(JsonNode userInfo) {
        String avatar = getField(userInfo, FLD_AVATAR_BIG);
        if (avatar != null) return avatar;
        avatar = getField(userInfo, FLD_AVATAR_MIDDLE);
        if (avatar != null) return avatar;
        avatar = getField(userInfo, FLD_AVATAR_THUMB);
        if (avatar != null) return avatar;
        return getField(userInfo, FLD_AVATAR_URL);
    }

    /**
     * Safe field accessor that handles missing, null, and empty-string values.
     */
    static String getField(JsonNode node, String field) {
        if (node == null || !node.has(field) || node.get(field).isNull()) {
            return null;
        }
        String value = node.get(field).asText();
        // Treat blank strings as "not present" for most purposes.
        if (value.isBlank()) {
            return null;
        }
        return value;
    }

    /**
     * Migrate a legacy federated identity link keyed by {@code open_id} to the
     * new {@code union_id} identifier.
     *
     * <p>Before the {@code union_id}-preferred change, the broker user ID was
     * set to the Feishu {@code open_id}. Existing federated user records are
     * therefore keyed by {@code open_id}.  On the first login after the upgrade
     * this method detects that mismatch and silently migrates the stored link
     * so that subsequent logins use {@code union_id} natively.</p>
     */
    private void migrateFederatedIdentityLink(RealmModel realm,
                                               BrokeredIdentityContext identity) {
        JsonNode userInfo = (JsonNode) identity.getContextData().get(PROP_FEISHU_USER_INFO);
        if (userInfo == null) {
            return;
        }

        String unionId = getField(userInfo, FLD_UNION_ID);
        String openId = getField(userInfo, FLD_OPEN_ID);
        if (unionId == null || openId == null || unionId.equals(openId)) {
            // Nothing to migrate – either one is missing or they already match.
            return;
        }

        String idpAlias = getConfig().getAlias();

        // Check whether a link already exists for the new union_id
        FederatedIdentityModel newLink = new FederatedIdentityModel(idpAlias, unionId, null);
        UserModel existingUser = session.users().getUserByFederatedIdentity(realm, newLink);
        if (existingUser != null) {
            // Already migrated by a previous login.
            return;
        }

        // Look for a legacy link keyed by open_id
        FederatedIdentityModel legacyLink = new FederatedIdentityModel(idpAlias, openId, null);
        UserModel legacyUser = session.users().getUserByFederatedIdentity(realm, legacyLink);
        if (legacyUser == null) {
            // No legacy link found – nothing to migrate.
            return;
        }

        logger.infof("Migrating federated identity link for user '%s': %s -> %s",
                legacyUser.getUsername(), openId, unionId);

        // Retrieve the existing federated identity to preserve the stored token
        FederatedIdentityModel existingFid = session.users()
                .getFederatedIdentity(realm, legacyUser, idpAlias);

        // Remove the legacy open_id link (idempotent), then add a new link with
        // union_id.  The order matters: remove first to free the unique constraint
        // on (user_id, identity_provider).
        session.users().removeFederatedIdentity(realm, legacyUser, idpAlias);
        try {
            session.users().addFederatedIdentity(realm, legacyUser,
                    new FederatedIdentityModel(idpAlias, unionId,
                            existingFid != null ? existingFid.getUserName() : identity.getUsername(),
                            existingFid != null ? existingFid.getToken() : identity.getToken()));
        } catch (Exception e) {
            // Check whether the failure was caused by a concurrent callback that
            // already added the union_id link before us.
            UserModel userByUnionId = session.users()
                    .getUserByFederatedIdentity(realm, newLink);
            if (userByUnionId != null) {
                // Concurrent migration completed — the old link is already removed.
                logger.debugf("Migration already completed by concurrent request " +
                        "for user '%s'", legacyUser.getUsername());
            } else {
                // Non-concurrency failure (e.g. transient DB error).  We have already
                // removed the legacy open_id link, so the user would be left without
                // any federated identity.  Propagate the exception to fail the login
                // safely rather than silently dropping the link.
                throw e;
            }
        }
    }
}
