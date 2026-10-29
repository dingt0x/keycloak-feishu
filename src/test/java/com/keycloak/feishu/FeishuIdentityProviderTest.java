package com.keycloak.feishu;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.IdentityProviderModel;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link FeishuIdentityProvider}.
 *
 * <p>These tests exercise the <strong>production</strong> code paths directly
 * ({@code unwrapUserInfoResponse}, {@code getField}, {@code pickAvatar} and
 * {@code buildIdentity}). No Keycloak session or live HTTP call is required:
 * the provider instance is built with a {@code null} session, which is safe
 * because none of the methods under test touch the session.</p>
 */
class FeishuIdentityProviderTest {

    /**
     * Realistic wrapped response from {@code /open-apis/authen/v1/user_info}.
     * Values are fake.
     */
    private static final String WRAPPED_RESPONSE = """
            {
              "code": 0,
              "data": {
                "avatar_big": "https://example.com/avatar/big.png",
                "avatar_middle": "https://example.com/avatar/mid.png",
                "avatar_thumb": "https://example.com/avatar/thumb.png",
                "avatar_url": "https://example.com/avatar/url.png",
                "email": "zhangsan@example.com",
                "en_name": "Zhang San",
                "mobile": "+8610000000000",
                "name": "张三",
                "open_id": "ou_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "tenant_key": "tt_aaaaaaaaaaaaaa",
                "union_id": "on_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "user_id": "usr_000001"
              },
              "msg": "success"
            }
            """;

    private FeishuIdentityProvider provider;

    @BeforeEach
    void setUp() {
        // Keycloak 26.5+ rejects a BrokeredIdentityContext built from a
        // disabled IdP model, so the model must be marked enabled.
        IdentityProviderModel model = new IdentityProviderModel();
        model.setEnabled(true);

        FeishuIdentityProviderConfig config = new FeishuIdentityProviderConfig(model);
        provider = new FeishuIdentityProvider(null, config);
    }

    // ========================================================================
    // Envelope handling  {code, msg, data}
    // ========================================================================

    @Nested
    @DisplayName("unwrapUserInfoResponse")
    class UnwrapUserInfoResponse {

        @Test
        void wrappedResponseReturnsDataPayload() throws Exception {
            JsonNode data = FeishuIdentityProvider.unwrapUserInfoResponse(WRAPPED_RESPONSE);

            assertEquals("张三", FeishuIdentityProvider.getField(data, "name"));
            assertEquals("on_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    FeishuIdentityProvider.getField(data, "union_id"));
            assertFalse(data.has("code"), "envelope fields must not leak into the payload");
        }

        @Test
        void nonZeroCodeThrowsWithFeishuMessage() {
            String body = """
                    {"code": 99991663, "msg": "invalid access token", "data": {}}
                    """;

            IdentityBrokerException ex = assertThrows(IdentityBrokerException.class,
                    () -> FeishuIdentityProvider.unwrapUserInfoResponse(body));
            assertTrue(ex.getMessage().contains("invalid access token"),
                    "Feishu's msg should be surfaced in the exception, got: " + ex.getMessage());
        }

        @Test
        void flatResponseIsReturnedAsIs() throws Exception {
            String body = """
                    {"name": "李四", "open_id": "ou_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
                    """;

            JsonNode data = FeishuIdentityProvider.unwrapUserInfoResponse(body);

            assertEquals("李四", FeishuIdentityProvider.getField(data, "name"));
        }
    }

    // ========================================================================
    // Field accessor
    // ========================================================================

    @Nested
    @DisplayName("getField")
    class GetField {

        @Test
        void returnsValueWhenPresent() throws Exception {
            JsonNode node = FeishuIdentityProvider.unwrapUserInfoResponse(WRAPPED_RESPONSE);
            assertEquals("+8610000000000", FeishuIdentityProvider.getField(node, "mobile"));
        }

        @Test
        void missingFieldReturnsNull() throws Exception {
            JsonNode node = FeishuIdentityProvider.unwrapUserInfoResponse(WRAPPED_RESPONSE);
            assertNull(FeishuIdentityProvider.getField(node, "sub"));
            assertNull(FeishuIdentityProvider.getField(node, "nickname"));
        }

        @Test
        void blankAndWhitespaceTreatedAsAbsent() throws Exception {
            JsonNode node = FeishuIdentityProvider.unwrapUserInfoResponse(
                    "{\"email\": \"\", \"name\": \"   \"}");
            assertNull(FeishuIdentityProvider.getField(node, "email"),
                    "empty string must be treated as absent (Feishu returns \"\" for unset email)");
            assertNull(FeishuIdentityProvider.getField(node, "name"));
        }

        @Test
        void explicitJsonNullReturnsNull() throws Exception {
            JsonNode node = FeishuIdentityProvider.unwrapUserInfoResponse("{\"mobile\": null}");
            assertNull(FeishuIdentityProvider.getField(node, "mobile"));
        }
    }

    // ========================================================================
    // Avatar selection
    // ========================================================================

    @Nested
    @DisplayName("pickAvatar")
    class PickAvatar {

        @Test
        void prefersBigThenMiddleThenThumbThenUrl() throws Exception {
            assertEquals("https://example.com/avatar/big.png",
                    FeishuIdentityProvider.pickAvatar(dataNodeOf(WRAPPED_RESPONSE)));

            assertEquals("mid", FeishuIdentityProvider.pickAvatar(dataNodeOf(
                    "{\"avatar_middle\": \"mid\", \"avatar_thumb\": \"thumb\", \"avatar_url\": \"url\"}")));

            assertEquals("thumb", FeishuIdentityProvider.pickAvatar(dataNodeOf(
                    "{\"avatar_thumb\": \"thumb\", \"avatar_url\": \"url\"}")));

            assertEquals("url", FeishuIdentityProvider.pickAvatar(dataNodeOf("{\"avatar_url\": \"url\"}")));
        }

        @Test
        void returnsNullWhenNoAvatarPresent() throws Exception {
            assertNull(FeishuIdentityProvider.pickAvatar(dataNodeOf("{\"name\": \"张三\"}")));
        }
    }

    // ========================================================================
    // Federated identity construction
    // ========================================================================

    @Nested
    @DisplayName("buildIdentity")
    class BuildIdentity {

        @Test
        void prefersUnionIdAsBrokerUserId() throws Exception {
            BrokeredIdentityContext identity =
                    provider.buildIdentity(dataNodeOf(WRAPPED_RESPONSE));

            assertEquals("on_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", identity.getId(),
                    "union_id is stable across apps and must win over open_id");
        }

        @Test
        void mapsNameToFirstNameAndLeavesLastNameEmpty() throws Exception {
            BrokeredIdentityContext identity =
                    provider.buildIdentity(dataNodeOf(WRAPPED_RESPONSE));

            assertEquals("张三", identity.getFirstName());
            assertNull(identity.getLastName(),
                    "Feishu has no separate surname field; setting lastName would duplicate the name");
        }

        @Test
        void setsEmailWhenPresent() throws Exception {
            BrokeredIdentityContext identity =
                    provider.buildIdentity(dataNodeOf(WRAPPED_RESPONSE));

            assertEquals("zhangsan@example.com", identity.getEmail());
        }

        @Test
        void skipsEmailWhenBlank() throws Exception {
            BrokeredIdentityContext identity = provider.buildIdentity(dataNodeOf(
                    "{\"union_id\": \"on_x\", \"name\": \"王五\", \"email\": \"\"}"));

            assertNull(identity.getEmail(), "blank email must not overwrite the Keycloak user's email");
        }

        @Test
        void fallsBackToOpenIdThenSub() throws Exception {
            assertEquals("ou_only",
                    provider.buildIdentity(dataNodeOf("{\"open_id\": \"ou_only\"}")).getId());

            assertEquals("sub_only",
                    provider.buildIdentity(dataNodeOf("{\"sub\": \"sub_only\"}")).getId());
        }

        @Test
        void throwsWhenNoIdentifierPresent() throws Exception {
            JsonNode data = dataNodeOf("{\"name\": \"无标识\"}");

            IdentityBrokerException ex = assertThrows(IdentityBrokerException.class,
                    () -> provider.buildIdentity(data));
            assertTrue(ex.getMessage().contains("union_id") || ex.getMessage().contains("open_id"));
        }

        @Test
        void storesRawUserInfoForAttributeMapper() throws Exception {
            JsonNode data = dataNodeOf(WRAPPED_RESPONSE);
            BrokeredIdentityContext identity = provider.buildIdentity(data);

            assertSame(data, identity.getContextData().get("feishuUserInfo"),
                    "the attribute mapper reads the raw payload from context data under 'feishuUserInfo'");
        }
    }

    // ========================================================================
    // FEISHU_DEBUG
    // ========================================================================

    @Nested
    @DisplayName("isFeishuDebugEnabled")
    class FeishuDebugFlag {

        @Test
        void acceptsOneAndTrueAfterTrimIgnoringCase() {
            assertTrue(FeishuIdentityProvider.isFeishuDebugEnabled("1"));
            assertTrue(FeishuIdentityProvider.isFeishuDebugEnabled(" 1 "));
            assertTrue(FeishuIdentityProvider.isFeishuDebugEnabled("true"));
            assertTrue(FeishuIdentityProvider.isFeishuDebugEnabled("TRUE"));
            assertTrue(FeishuIdentityProvider.isFeishuDebugEnabled(" True "));
        }

        @Test
        void rejectsMissingBlankAndOtherValues() {
            assertFalse(FeishuIdentityProvider.isFeishuDebugEnabled(null));
            assertFalse(FeishuIdentityProvider.isFeishuDebugEnabled(""));
            assertFalse(FeishuIdentityProvider.isFeishuDebugEnabled("   "));
            assertFalse(FeishuIdentityProvider.isFeishuDebugEnabled("0"));
            assertFalse(FeishuIdentityProvider.isFeishuDebugEnabled("false"));
            assertFalse(FeishuIdentityProvider.isFeishuDebugEnabled("yes"));
            assertFalse(FeishuIdentityProvider.isFeishuDebugEnabled("truee"));
        }
    }

    // ========================================================================
    // Helper
    // ========================================================================

    private static JsonNode dataNodeOf(String json) throws Exception {
        return FeishuIdentityProvider.unwrapUserInfoResponse(json);
    }
}
