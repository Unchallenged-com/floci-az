package io.floci.az.services.graph;

import io.floci.az.services.entra.EntraStore;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@DisplayName("Microsoft Graph directory audits: every directory change Graph serves, read through auditLogs/directoryAudits")
class GraphDirectoryAuditsTest {

    private static final String TENANT = "00000000-0000-0000-0000-000000000002";
    private static final String AUDITS = "/v1.0/auditLogs/directoryAudits";
    private static final String DIRECTORY_OBJECTS = "https://graph.microsoft.com/v1.0/directoryObjects/";

    @BeforeEach
    void reset() {
        given().when().post("/_admin/reset").then().statusCode(204);
    }

    private static String userToken() {
        return given().contentType("application/x-www-form-urlencoded").formParam("grant_type", "password")
                .formParam("client_id", EntraStore.DEV_CLIENT_ID).formParam("username", EntraStore.DEV_USER_UPN)
                .formParam("password", "any").formParam("scope", "https://graph.microsoft.com/.default")
                .post("/" + TENANT + "/oauth2/v2.0/token").then().statusCode(200).extract().path("access_token");
    }

    private static String appToken() {
        return given().contentType("application/x-www-form-urlencoded").formParam("grant_type", "client_credentials")
                .formParam("client_id", EntraStore.DEV_CLIENT_ID).formParam("client_secret", EntraStore.DEV_CLIENT_SECRET)
                .formParam("scope", "https://graph.microsoft.com/.default")
                .post("/" + TENANT + "/oauth2/v2.0/token").then().statusCode(200).extract().path("access_token");
    }

    private static String createApp(String token, String name) {
        return given().header("Authorization", "Bearer " + token).header("User-Agent", "audit-test/1.0")
                .contentType("application/json").body("{\"displayName\": \"" + name + "\"}")
                .post("/v1.0/applications").then().statusCode(201).extract().path("id");
    }

    private static JsonPath audits(Map<String, ?> query) {
        return given().queryParams(query).get(AUDITS).then().statusCode(200).extract().jsonPath();
    }

    private static Map<String, Object> only(String activity) {
        JsonPath page = audits(Map.of("$filter", "activityDisplayName eq '" + activity + "'"));
        assertEquals(1, page.getList("value").size(), activity);
        return page.getMap("value[0]");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> property(Map<String, Object> target, String name) {
        return ((List<Map<String, Object>>) target.get("modifiedProperties")).stream()
                .filter(p -> name.equals(p.get("displayName"))).findFirst()
                .orElseThrow(() -> new AssertionError("no modified property " + name + " in " + target));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> target(Map<String, Object> audit, int index) {
        return ((List<Map<String, Object>>) audit.get("targetResources")).get(index);
    }

    @SuppressWarnings("unchecked")
    private static String detail(Map<String, Object> audit, String key) {
        return ((List<Map<String, Object>>) audit.get("additionalDetails")).stream()
                .filter(d -> key.equals(d.get("key"))).map(d -> (String) d.get("value")).findFirst().orElse(null);
    }

    @Test
    @SuppressWarnings("unchecked")
    void creatingAnApplicationLogsTheApplicationItsServicePrincipalAndItsFirstOwner() {
        String objectId = createApp(userToken(), "audited");
        String appId = given().get("/v1.0/applications/" + objectId).then().extract().path("appId");

        JsonPath page = audits(Map.of());
        assertEquals("https://graph.microsoft.com/v1.0/$metadata#auditLogs/directoryAudits",
                page.getString("'@odata.context'"));
        assertEquals(3, page.getList("value").size());

        Map<String, Object> add = only("Add application");
        assertEquals("ApplicationManagement", add.get("category"));
        assertEquals("Core Directory", add.get("loggedByService"));
        assertEquals("Add", add.get("operationType"));
        assertEquals("success", add.get("result"));
        assertEquals("", add.get("resultReason"));
        assertThat((String) add.get("id"), startsWith("Directory_" + add.get("correlationId") + "_"));
        assertTrue(!Instant.parse((String) add.get("activityDateTime")).isAfter(Instant.now()));
        Map<String, Object> user = (Map<String, Object>) ((Map<String, Object>) add.get("initiatedBy")).get("user");
        assertEquals(EntraStore.DEV_USER_OBJECT_ID, user.get("id"));
        assertEquals(EntraStore.DEV_USER_UPN, user.get("userPrincipalName"));
        assertNotNull(user.get("ipAddress"));
        assertNull(((Map<String, Object>) add.get("initiatedBy")).get("app"));
        Map<String, Object> app = target(add, 0);
        assertEquals(objectId, app.get("id"));
        assertEquals("audited", app.get("displayName"));
        assertEquals("Application", app.get("type"));
        assertEquals("[\"" + appId + "\"]", property(app, "AppId").get("newValue"));
        assertEquals("[]", property(app, "AppId").get("oldValue"));
        assertEquals("[\"audited\"]", property(app, "DisplayName").get("newValue"));
        assertEquals("\"AppId, DisplayName\"", property(app, "Included Updated Properties").get("newValue"));
        assertEquals("audit-test/1.0", detail(add, "User-Agent"));
        assertEquals(appId, detail(add, "AppId"));

        Map<String, Object> sp = only("Add service principal");
        assertEquals("Add", sp.get("operationType"));
        assertEquals(add.get("correlationId"), sp.get("correlationId"), "one request, one correlation id");
        Map<String, Object> principal = target(sp, 0);
        assertEquals("ServicePrincipal", principal.get("type"));
        assertEquals("[true]", property(principal, "AccountEnabled").get("newValue"));
        assertEquals("[\"" + appId + "\"]", property(principal, "AppPrincipalId").get("newValue"));

        Map<String, Object> owner = only("Add owner to application");
        assertEquals("Assign", owner.get("operationType"));
        Map<String, Object> added = target(owner, 0);
        assertEquals("User", added.get("type"));
        assertEquals(EntraStore.DEV_USER_OBJECT_ID, added.get("id"));
        assertEquals(EntraStore.DEV_USER_UPN, added.get("userPrincipalName"));
        assertEquals("\"audited\"", property(added, "Application.DisplayName").get("newValue"));
        assertEquals("Application", target(owner, 1).get("type"));
        assertEquals(objectId, target(owner, 1).get("id"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void secretsUpdatesOwnersAndDeletionAreLoggedAndAnAppCallerIsTheInitiator() {
        String token = appToken();
        String objectId = createApp(token, "secrets");
        String keyId = given().header("Authorization", "Bearer " + token).contentType("application/json")
                .body("{\"passwordCredential\": {\"displayName\": \"ci\"}}")
                .post("/v1.0/applications/" + objectId + "/addPassword").then().statusCode(200).extract().path("keyId");

        Map<String, Object> added = only("Update application - Certificates and secrets management");
        assertEquals("Update", added.get("operationType"));
        Map<String, Object> app = (Map<String, Object>) ((Map<String, Object>) added.get("initiatedBy")).get("app");
        assertEquals(EntraStore.DEV_CLIENT_ID, app.get("appId"));
        assertEquals(EntraStore.DEV_SP_OBJECT_ID, app.get("servicePrincipalId"));
        assertNull(((Map<String, Object>) added.get("initiatedBy")).get("user"));
        Map<String, Object> keys = property(target(added, 0), "KeyDescription");
        assertEquals("[]", keys.get("oldValue"));
        assertEquals("[\"[KeyIdentifier=" + keyId + ",KeyType=Password,KeyUsage=Verify,DisplayName=ci]\"]",
                keys.get("newValue"));

        given().contentType("application/json").body("{\"keyId\": \"" + keyId + "\"}")
                .post("/v1.0/applications/" + objectId + "/removePassword").then().statusCode(204);
        JsonPath secrets = audits(Map.of("$filter",
                "activityDisplayName eq 'Update application - Certificates and secrets management'"));
        assertEquals(2, secrets.getList("value").size());
        Map<String, Object> removed = secrets.getMap("value[0]");
        assertEquals(keys.get("newValue"), property(target(removed, 0), "KeyDescription").get("oldValue"), "newest first");
        assertEquals("[]", property(target(removed, 0), "KeyDescription").get("newValue"));
        assertNull(((Map<String, Object>) removed.get("initiatedBy")).get("user"), "no token, no initiator");
        assertNull(((Map<String, Object>) removed.get("initiatedBy")).get("app"));

        given().contentType("application/json").body("{\"displayName\": \"renamed\"}")
                .patch("/v1.0/applications/" + objectId).then().statusCode(204);
        Map<String, Object> update = only("Update application");
        Map<String, Object> name = property(target(update, 0), "DisplayName");
        assertEquals("[\"secrets\"]", name.get("oldValue"));
        assertEquals("[\"renamed\"]", name.get("newValue"));

        given().contentType("application/json").body("{\"@odata.id\": \"" + DIRECTORY_OBJECTS + EntraStore.DEV_USER_OBJECT_ID + "\"}")
                .post("/v1.0/applications/" + objectId + "/owners/$ref").then().statusCode(204);
        given().delete("/v1.0/applications/" + objectId + "/owners/" + EntraStore.DEV_USER_OBJECT_ID + "/$ref")
                .then().statusCode(204);
        Map<String, Object> unowned = only("Remove owner from application");
        assertEquals("Unassign", unowned.get("operationType"));
        assertEquals("\"renamed\"", property(target(unowned, 0), "Application.DisplayName").get("oldValue"));

        given().delete("/v1.0/applications/" + objectId).then().statusCode(204);
        assertEquals("Delete", only("Delete application").get("operationType"));
        assertEquals("Delete", only("Remove service principal").get("operationType"));

        // A refused write changes nothing and logs nothing.
        given().contentType("application/json").body("{\"keyId\": \"" + keyId + "\"}")
                .post("/v1.0/applications/" + objectId + "/removePassword").then().statusCode(404);
        assertEquals(2, audits(Map.of("$filter",
                "activityDisplayName eq 'Update application - Certificates and secrets management'")).getList("value").size());
    }

    @Test
    void groupMembershipChangesAreLoggedWithTheGroupOnTheMember() {
        // The dev service principal joins and leaves the dev group, which keeps its seeded members.
        given().contentType("application/json").body("{\"@odata.id\": \"" + DIRECTORY_OBJECTS + EntraStore.DEV_SP_OBJECT_ID + "\"}")
                .post("/v1.0/groups/" + EntraStore.DEV_GROUP_OBJECT_ID + "/members/$ref").then().statusCode(204);
        given().delete("/v1.0/groups/" + EntraStore.DEV_GROUP_OBJECT_ID + "/members/" + EntraStore.DEV_SP_OBJECT_ID + "/$ref")
                .then().statusCode(204);

        Map<String, Object> add = only("Add member to group");
        assertEquals("GroupManagement", add.get("category"));
        assertEquals("Assign", add.get("operationType"));
        Map<String, Object> member = target(add, 0);
        assertEquals("ServicePrincipal", member.get("type"));
        assertEquals(EntraStore.DEV_SP_OBJECT_ID, member.get("id"));
        assertNull(member.get("userPrincipalName"));
        assertEquals("\"" + EntraStore.DEV_GROUP_OBJECT_ID + "\"", property(member, "Group.ObjectID").get("newValue"));
        assertEquals("\"" + EntraStore.DEV_GROUP_NAME + "\"", property(member, "Group.DisplayName").get("newValue"));
        assertEquals("Group", target(add, 1).get("type"));

        Map<String, Object> remove = only("Remove member from group");
        assertEquals("Unassign", remove.get("operationType"));
        assertEquals("\"" + EntraStore.DEV_GROUP_OBJECT_ID + "\"",
                property(target(remove, 0), "Group.ObjectID").get("oldValue"));
        assertNull(property(target(remove, 0), "Group.ObjectID").get("newValue"));

        // Removing a principal that is not a member changes nothing and logs nothing.
        given().delete("/v1.0/groups/" + EntraStore.DEV_GROUP_OBJECT_ID + "/members/" + EntraStore.DEV_SP_OBJECT_ID + "/$ref")
                .then().statusCode(204);
        only("Remove member from group");
    }

    @Test
    void theListFiltersOrdersPagesAndGetsByIdAsGraphDoes() {
        Instant before = Instant.now().minusSeconds(5);
        String token = userToken();
        String first = createApp(token, "alpha");
        createApp(token, "beta");

        assertEquals(6, audits(Map.of("$filter", "activityDateTime ge " + before)).getList("value").size());
        assertEquals(0, audits(Map.of("$filter", "activityDateTime le " + before)).getList("value").size());
        assertEquals(2, audits(Map.of("$filter", "startswith(activityDisplayName,'Add app')")).getList("value").size());
        assertEquals(6, audits(Map.of("$filter", "loggedByService eq 'Core Directory' and initiatedBy/user/userPrincipalName eq '"
                + EntraStore.DEV_USER_UPN + "'")).getList("value").size());
        assertEquals(6, audits(Map.of("$filter", "initiatedBy/user/id eq '" + EntraStore.DEV_USER_OBJECT_ID + "'"))
                .getList("value").size());
        assertEquals(2, audits(Map.of("$filter", "targetResources/any(t: t/id eq '" + first + "')")).getList("value").size(),
                "the application, and the owner entry that names it");
        assertEquals(3, audits(Map.of("$filter", "targetResources/any(t: startswith(t/displayName,'alph'))"))
                .getList("value").size(), "the application, its service principal and the owner entry");

        JsonPath page = audits(Map.of("$top", "4"));
        assertEquals(4, page.getList("value").size());
        String next = page.getString("'@odata.nextLink'");
        assertThat(next, startsWith("https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?"));
        String skip = URI.create(next).getQuery().replaceFirst(".*\\$skiptoken=([^&]+).*", "$1");
        JsonPath rest = audits(Map.of("$top", "4", "$skiptoken", skip));
        assertEquals(2, rest.getList("value").size());
        assertNull(rest.get("'@odata.nextLink'"));

        String newest = audits(Map.of()).getString("value[0].targetResources[1].displayName");
        String oldest = audits(Map.of("$orderby", "activityDateTime asc")).getString("value[0].targetResources[0].displayName");
        assertEquals("beta", newest);
        assertEquals("alpha", oldest);

        String id = audits(Map.of()).getString("value[0].id");
        given().get(AUDITS + "/" + id).then().statusCode(200).body("id", is(id))
                .body("'@odata.context'", is("https://graph.microsoft.com/v1.0/$metadata#auditLogs/directoryAudits/$entity"));
        given().get(AUDITS + "/Directory_unknown").then().statusCode(404);
        given().queryParam("$filter", "result eq 'success'").get(AUDITS).then().statusCode(400)
                .body("error.code", is("Request_BadRequest"));
        given().post(AUDITS).then().statusCode(405);
    }
}
