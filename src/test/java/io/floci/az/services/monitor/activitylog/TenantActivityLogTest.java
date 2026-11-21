package io.floci.az.services.monitor.activitylog;

import io.floci.az.services.entra.EntraStore;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.isOneOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@DisplayName("Activity Log: tenant-level and management-group-level entries for ARM writes outside a subscription")
class TenantActivityLogTest {

    private static final String TENANT = "00000000-0000-0000-0000-000000000002";
    private static final String SUB = "00000000-0000-0000-0000-000000000001";
    private static final String MG = "/providers/Microsoft.Management/managementGroups/mg-audit";
    private static final String OTHER_MG = "/providers/Microsoft.Management/managementGroups/mg-other";
    private static final String OWNER = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
    private static final String MG_ASSIGNMENT = MG + "/providers/Microsoft.Authorization/roleAssignments/11111111-aaaa-4aaa-8aaa-000000000001";
    private static final String ROOT_ASSIGNMENT = "/providers/Microsoft.Authorization/roleAssignments/11111111-aaaa-4aaa-8aaa-000000000002";
    private static final String TENANT_LOGS = "/providers/Microsoft.Insights/eventtypes/management/values";
    private static final String MG_LOGS = MG + "/providers/Microsoft.Insights/eventtypes/management/values";
    private static final String SUB_LOGS = "/subscriptions/" + SUB + "/providers/Microsoft.Insights/eventtypes/management/values";

    private String since;
    private String token;

    @BeforeEach
    void reset() {
        given().when().post("/_admin/reset").then().statusCode(204);
        since = Instant.now().minusSeconds(60).toString();
        token = given().contentType("application/x-www-form-urlencoded").formParam("grant_type", "client_credentials")
                .formParam("client_id", EntraStore.DEV_CLIENT_ID).formParam("client_secret", EntraStore.DEV_CLIENT_SECRET)
                .formParam("scope", "https://management.azure.com/.default")
                .post("/" + TENANT + "/oauth2/v2.0/token").then().statusCode(200).extract().path("access_token");
    }

    private void put(String id, String apiVersion, String body) {
        given().header("Authorization", "Bearer " + token).contentType("application/json").body(body)
                .when().put(id + "?api-version=" + apiVersion).then().statusCode(isOneOf(200, 201, 202));
    }

    private static String assignment(String principal) {
        return "{\"properties\": {\"roleDefinitionId\": \"" + OWNER + "\", \"principalId\": \"" + principal
                + "\", \"principalType\": \"ServicePrincipal\"}}";
    }

    private JsonPath list(String path, String apiVersion, String filter) {
        return given().queryParam("api-version", apiVersion).queryParam("$filter", filter)
                .when().get(path).then().statusCode(200).extract().jsonPath();
    }

    private JsonPath tenantLog() {
        return list(TENANT_LOGS, "2015-04-01", "eventTimestamp ge '" + since + "'");
    }

    @Test
    void writesAtTheTenantRootAndOnManagementGroupsAreInTheTenantLog() {
        put(MG, "2021-04-01", "{\"properties\": {\"displayName\": \"Audit\"}}");
        put(MG_ASSIGNMENT, "2022-04-01", assignment(EntraStore.DEV_SP_OBJECT_ID));
        put(ROOT_ASSIGNMENT, "2022-04-01", assignment(EntraStore.DEV_SP_OBJECT_ID));

        JsonPath log = tenantLog();
        List<String> operations = log.getList("value.operationName.value");
        assertEquals(6, operations.size(), "a begin and an end entry per write: " + operations);
        assertEquals("Microsoft.Authorization/roleAssignments/write", log.getString("value[0].operationName.value"));
        assertEquals(ROOT_ASSIGNMENT, log.getString("value[0].resourceId"));
        assertEquals("Microsoft.Authorization/roleAssignments/write", log.getString("value[0].authorization.action"));
        assertEquals(ROOT_ASSIGNMENT, log.getString("value[0].authorization.scope"));
        assertEquals("EndRequest", log.getString("value[0].eventName.value"));
        assertEquals("Succeeded", log.getString("value[0].status.value"));
        assertEquals("", log.getString("value[0].subscriptionId"), "a tenant-level entry names no subscription");
        assertEquals(TENANT, log.getString("value[0].tenantId"));
        assertEquals(EntraStore.DEV_SP_OBJECT_ID, log.getString("value[0].caller"));
        assertTrue(operations.contains("Microsoft.Management/managementGroups/write"));
        assertEquals(MG_ASSIGNMENT, log.getString("value[2].resourceId"));

        JsonPath subscription = list(SUB_LOGS, "2015-04-01", "eventTimestamp ge '" + since + "'");
        assertFalse(subscription.getList("value.resourceId").contains(MG_ASSIGNMENT),
                "the subscription log holds none of them");
    }

    @Test
    void aManagementGroupLogHoldsTheEntriesScopedToThatGroup() {
        put(MG, "2021-04-01", "{\"properties\": {\"displayName\": \"Audit\"}}");
        put(OTHER_MG, "2021-04-01", "{\"properties\": {\"displayName\": \"Other\"}}");
        put(MG_ASSIGNMENT, "2022-04-01", assignment(EntraStore.DEV_SP_OBJECT_ID));
        put(ROOT_ASSIGNMENT, "2022-04-01", assignment(EntraStore.DEV_SP_OBJECT_ID));
        put(MG + "/subscriptions/" + SUB, "2021-04-01", "{}");

        JsonPath log = list(MG_LOGS, "2017-03-01-preview", "eventTimestamp ge '" + since + "'");
        List<String> resources = log.getList("value.resourceId");
        assertEquals(6, resources.size(), "the group, its role assignment and its new subscription: " + resources);
        assertTrue(resources.contains(MG));
        assertTrue(resources.contains(MG_ASSIGNMENT));
        assertTrue(resources.contains(MG + "/subscriptions/" + SUB));
        assertFalse(resources.contains(OTHER_MG));
        assertFalse(resources.contains(ROOT_ASSIGNMENT));
        assertEquals(List.of("Microsoft.Management/managementGroups/subscriptions/write",
                "Microsoft.Management/managementGroups/subscriptions/write"),
                log.getList("value.findAll { it.resourceId.endsWith('/subscriptions/" + SUB + "') }.operationName.value"));
    }

    @Test
    void theTenantListTakesTheListFilterAndRefusesAFilterWithoutAStart() {
        put(MG, "2021-04-01", "{\"properties\": {\"displayName\": \"Audit\"}}");
        put(ROOT_ASSIGNMENT, "2022-04-01", assignment(EntraStore.DEV_SP_OBJECT_ID));

        JsonPath filtered = list(TENANT_LOGS, "2015-04-01", "eventTimestamp ge '" + since
                + "' and resourceProvider eq 'Microsoft.Authorization'");
        assertEquals(2, filtered.getList("value").size());

        given().queryParam("api-version", "2015-04-01").queryParam("$filter", "resourceProvider eq 'Microsoft.Authorization'")
                .when().get(TENANT_LOGS).then().statusCode(400).body("code", equalTo("BadRequest"));
    }
}
