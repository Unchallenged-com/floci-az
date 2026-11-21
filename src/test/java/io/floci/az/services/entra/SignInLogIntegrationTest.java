package io.floci.az.services.entra;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.json.JsonPath;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@TestProfile(SignInLogIntegrationTest.Validating.class)
@DisplayName("Entra sign-in logs: every token request and authorize approval, read through Graph auditLogs/signIns")
class SignInLogIntegrationTest {

    private static final String TENANT = "00000000-0000-0000-0000-000000000002";
    private static final String TOKEN = "/" + TENANT + "/oauth2/v2.0/token";
    private static final String AUTHORIZE = "/" + TENANT + "/oauth2/v2.0/authorize";
    private static final String V1 = "/v1.0/auditLogs/signIns";
    private static final String BETA = "/beta/auditLogs/signIns";
    private static final String PASSWORD = "sign-in-log-test-password";
    private static final String GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";

    @Inject GraphDirectoryStore directory;
    @Inject SignInLog signIns;

    private DirectoryObject user;
    private String upn;

    public static class Validating implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci-az.services.entra.validate-user-credentials", "true",
                    "floci-az.services.entra.validate-client-credentials", "true");
        }
    }

    @BeforeEach
    void provisionAUserAndStartFromAnEmptyLog() {
        signIns.clear();
        String id = UUID.randomUUID().toString();
        upn = "Sign.In." + id + "@local.invalid";
        user = GraphDirectoryStore.user(TENANT, id, upn, "Sign-in log user", upn);
        user.props().put("accountEnabled", true);
        user.props().putObject("passwordProfile").put("password", PASSWORD)
                .put("forceChangePasswordNextSignIn", false);
        directory.put(user);
    }

    @AfterEach
    void removeTheFixture() {
        directory.delete(TENANT, DirectoryEntitySet.USERS, user.id());
        signIns.clear();
    }

    private static RequestSpecification form(String correlationId) {
        RequestSpecification spec = given().contentType("application/x-www-form-urlencoded");
        return correlationId == null ? spec : spec.header("client-request-id", correlationId);
    }

    private io.restassured.response.Response password(String password, String scope, String correlationId) {
        return form(correlationId).formParam("grant_type", "password")
                .formParam("client_id", EntraStore.DEV_CLIENT_ID).formParam("client_secret", EntraStore.DEV_CLIENT_SECRET)
                .formParam("username", upn).formParam("password", password).formParam("scope", scope)
                .post(TOKEN);
    }

    private static JsonPath list(String path, Map<String, ?> query) {
        return given().queryParams(query).get(path).then().statusCode(200).extract().jsonPath();
    }

    private static JsonPath list(String path) {
        return list(path, Map.of());
    }

    @Test
    void aFailedPasswordSignInIsLoggedAsAnInteractiveSignInWithItsAadstsCode() {
        String correlationId = UUID.randomUUID().toString();
        password("wrong-password", "openid https://graph.microsoft.com/User.Read", correlationId)
                .then().statusCode(400).body("error_codes[0]", is(50126));

        JsonPath page = list(V1);
        assertEquals("https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns", page.getString("'@odata.context'"));
        assertEquals(1, page.getList("value").size());
        Map<String, Object> signIn = page.getMap("value[0]");
        assertEquals(upn.toLowerCase(), signIn.get("userPrincipalName"), "the log keeps the name in lowercase");
        assertEquals(user.id(), signIn.get("userId"));
        assertEquals("Sign-in log user", signIn.get("userDisplayName"));
        assertEquals(EntraStore.DEV_CLIENT_ID, signIn.get("appId"));
        assertEquals(correlationId, signIn.get("correlationId"));
        assertEquals(Boolean.TRUE, signIn.get("isInteractive"));
        assertEquals("notApplied", signIn.get("conditionalAccessStatus"));
        assertEquals(GRAPH_APP_ID, signIn.get("resourceId"));
        assertEquals("Microsoft Graph", signIn.get("resourceDisplayName"));
        assertNotNull(signIn.get("ipAddress"));
        assertEquals(50126, page.getInt("value[0].status.errorCode"));
        assertEquals("Error validating credentials due to invalid username or password.",
                page.getString("value[0].status.failureReason"));
        assertFalse(signIn.containsKey("signInEventTypes"), "v1.0 serves no beta property");
        Instant created = Instant.parse((String) signIn.get("createdDateTime"));
        assertTrue(!created.isAfter(Instant.now()));
    }

    @Test
    void aSuccessfulPasswordSignInHasErrorCodeZeroAndCanBeReadById() {
        password(PASSWORD, "openid api://resource/read", null).then().statusCode(200);

        JsonPath page = list(V1);
        assertEquals(1, page.getList("value").size());
        assertEquals(0, page.getInt("value[0].status.errorCode"));
        assertNull(page.get("value[0].status.failureReason"));
        assertNotNull(page.getString("value[0].correlationId"), "a correlation id is made up when the client sends none");
        String id = page.getString("value[0].id");

        given().get(V1 + "/" + id).then().statusCode(200)
                .body("id", is(id))
                .body("'@odata.context'", is("https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns/$entity"))
                .body("userId", is(user.id()));
        given().get(V1 + "/" + UUID.randomUUID()).then().statusCode(404);
    }

    @Test
    void refreshTokenRedemptionsAreNonInteractiveAndListedOnlyThroughBetaSignInEventTypes() {
        String refresh = password(PASSWORD, "openid offline_access api://resource/read", null)
                .then().statusCode(200).extract().path("refresh_token");
        form(null).formParam("grant_type", "refresh_token").formParam("client_id", EntraStore.DEV_CLIENT_ID)
                .formParam("client_secret", EntraStore.DEV_CLIENT_SECRET).formParam("refresh_token", refresh)
                .post(TOKEN).then().statusCode(200);

        assertEquals(1, list(V1).getList("value").size(), "v1.0 lists the interactive sign-in only");
        assertEquals(1, list(BETA).getList("value").size(), "beta lists interactive sign-ins unless filtered");

        JsonPath nonInteractive = list(BETA, Map.of("$filter", "signInEventTypes/any(t: t eq 'nonInteractiveUser')"));
        assertEquals(1, nonInteractive.getList("value").size());
        assertEquals(List.of("nonInteractiveUser"), nonInteractive.getList("value[0].signInEventTypes"));
        assertEquals(Boolean.FALSE, nonInteractive.get("value[0].isInteractive"));
        assertEquals(user.id(), nonInteractive.getString("value[0].userId"));
        assertEquals(TENANT, nonInteractive.getString("value[0].homeTenantId"));
        assertEquals("member", nonInteractive.getString("value[0].userType"));

        JsonPath both = list(BETA, Map.of("$filter",
                "signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')"));
        assertEquals(2, both.getList("value").size());
    }

    @Test
    void clientCredentialTokensAreServicePrincipalSignInsAndAWrongSecretIsLoggedWithItsCode() {
        form(null).formParam("grant_type", "client_credentials").formParam("client_id", EntraStore.DEV_CLIENT_ID)
                .formParam("client_secret", EntraStore.DEV_CLIENT_SECRET)
                .formParam("scope", "https://graph.microsoft.com/.default").post(TOKEN).then().statusCode(200);
        form(null).formParam("grant_type", "client_credentials").formParam("client_id", EntraStore.DEV_CLIENT_ID)
                .formParam("client_secret", "not-the-secret")
                .formParam("scope", "https://graph.microsoft.com/.default").post(TOKEN).then().statusCode(401);

        assertEquals(0, list(V1).getList("value").size(), "service principal sign-ins are not user sign-ins");

        JsonPath page = list(BETA, Map.of("$filter", "signInEventTypes/any(t: t eq 'servicePrincipal')"));
        assertEquals(2, page.getList("value").size());
        assertEquals(7000215, page.getInt("value[0].status.errorCode"), "newest first");
        assertEquals(0, page.getInt("value[1].status.errorCode"));
        assertEquals(EntraStore.DEV_SP_OBJECT_ID, page.getString("value[1].servicePrincipalId"));
        assertEquals("clientSecret", page.getString("value[1].clientCredentialType"));
        assertEquals(GRAPH_APP_ID, page.getString("value[1].resourceId"));
        assertNull(page.get("value[1].userId"));
        assertNull(page.get("value[1].homeTenantId"));

        JsonPath failures = list(BETA, Map.of("$filter",
                "signInEventTypes/any(t: t eq 'servicePrincipal') and status/errorCode eq 7000215"));
        assertEquals(1, failures.getList("value").size());
    }

    @Test
    void anAuthorizeApprovalIsAnInteractiveBrowserSignInAndItsCodeRedemptionIsNonInteractive() {
        String redirect = "https://local.invalid/callback";
        String location = given().redirects().follow(false).queryParam("client_id", EntraStore.DEV_CLIENT_ID)
                .queryParam("redirect_uri", redirect).queryParam("response_type", "code")
                .queryParam("scope", "openid api://resource/read").queryParam("login_hint", upn)
                .get(AUTHORIZE).then().statusCode(302).extract().header("Location");
        String code = URI.create(location).getQuery().replaceFirst(".*code=([^&]+).*", "$1");
        form(null).formParam("grant_type", "authorization_code").formParam("client_id", EntraStore.DEV_CLIENT_ID)
                .formParam("client_secret", EntraStore.DEV_CLIENT_SECRET).formParam("code", code)
                .formParam("redirect_uri", redirect).post(TOKEN).then().statusCode(200);

        JsonPath interactive = list(V1);
        assertEquals(1, interactive.getList("value").size());
        assertEquals("Browser", interactive.getString("value[0].clientAppUsed"));
        assertEquals(user.id(), interactive.getString("value[0].userId"));

        JsonPath redemption = list(BETA, Map.of("$filter", "signInEventTypes/any(t: t eq 'nonInteractiveUser')"));
        assertEquals(1, redemption.getList("value").size());
        assertEquals(user.id(), redemption.getString("value[0].userId"));
    }

    @Test
    void theListFiltersOrdersAndPagesAsGraphDoes() {
        Instant before = Instant.now().minusSeconds(5);
        for (int i = 0; i < 3; i++) {
            password("wrong-" + i, "openid", null).then().statusCode(400);
        }
        password(PASSWORD, "openid", null).then().statusCode(200);

        assertEquals(4, list(V1, Map.of("$filter", "createdDateTime ge " + before)).getList("value").size());
        assertEquals(0, list(V1, Map.of("$filter", "createdDateTime le " + before)).getList("value").size());
        assertEquals(3, list(V1, Map.of("$filter", "status/errorCode eq 50126")).getList("value").size());
        assertEquals(4, list(V1, Map.of("$filter", "userPrincipalName eq '" + upn + "'")).getList("value").size(),
                "string comparisons ignore case");
        assertEquals(4, list(V1, Map.of("$filter",
                "startsWith(userPrincipalName,'sign.in.') and appId eq '" + EntraStore.DEV_CLIENT_ID + "'"))
                .getList("value").size());

        JsonPath first = list(V1, Map.of("$top", "3"));
        assertEquals(3, first.getList("value").size());
        assertEquals(0, first.getInt("value[0].status.errorCode"), "newest first");
        String next = first.getString("'@odata.nextLink'");
        assertThat(next, startsWith("https://graph.microsoft.com/v1.0/auditLogs/signIns?"));
        String token = URI.create(next).getQuery().replaceFirst(".*\\$skiptoken=([^&]+).*", "$1");
        JsonPath second = list(V1, Map.of("$top", "3", "$skiptoken", token));
        assertEquals(1, second.getList("value").size());
        assertNull(second.get("'@odata.nextLink'"));

        JsonPath ascending = list(V1, Map.of("$orderby", "createdDateTime asc"));
        assertEquals(50126, ascending.getInt("value[0].status.errorCode"));

        given().queryParam("$filter", "isInteractive eq true").get(V1).then().statusCode(400)
                .body("error.code", is("Request_BadRequest"));
        given().queryParam("$skiptoken", "not-a-token").get(V1).then().statusCode(400);
        given().queryParam("$top", "1001").get(V1).then().statusCode(400);
    }
}
