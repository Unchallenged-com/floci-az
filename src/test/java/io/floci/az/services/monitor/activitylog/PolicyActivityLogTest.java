package io.floci.az.services.monitor.activitylog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.isOneOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@DisplayName("Activity Log: Policy entries for the deny and audit effects that fire on a write")
class PolicyActivityLogTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String TENANT = "00000000-0000-0000-0000-000000000002";
    private static final String SUB = "00000000-0000-0000-0000-000000000001";
    private static final String SUB_SCOPE = "/subscriptions/" + SUB;
    private static final String RG_SCOPE = SUB_SCOPE + "/resourceGroups/rg-policy-log";
    private static final String AUTH = "/providers/Microsoft.Authorization";
    private static final String DEFINITIONS = SUB_SCOPE + AUTH + "/policyDefinitions";
    private static final String ASSIGNMENTS = RG_SCOPE + AUTH + "/policyAssignments";
    private static final String MG = "policy-log-mg";
    private static final String POLICY_API = "?api-version=2025-03-01";
    private static final String STORAGE_API = "?api-version=2023-01-01";
    private static final String TLS_RULE = """
            {"if": {"allOf": [
                {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
                {"field": "Microsoft.Storage/storageAccounts/minimumTlsVersion", "notEquals": "TLS1_2"}]},
             "then": {"effect": "%s"}}""";

    private String since;

    @BeforeEach
    void reset() {
        given().when().post("/_admin/reset").then().statusCode(204);
        since = Instant.now().minusSeconds(60).toString();
        given().contentType("application/json").body("{\"properties\": {\"displayName\": \"Policy log\"}}")
                .when().put("/providers/Microsoft.Management/managementGroups/" + MG + "?api-version=2021-04-01")
                .then().statusCode(isOneOf(200, 201, 202));
        given().contentType("application/json").body("{}")
                .when().put("/providers/Microsoft.Management/managementGroups/" + MG + "/subscriptions/" + SUB
                        + "?api-version=2021-04-01").then().statusCode(isOneOf(200, 201, 204));
        given().contentType("application/json").body("{\"location\": \"eastus\"}")
                .when().put(RG_SCOPE + "?api-version=2021-04-01").then().statusCode(isOneOf(200, 201));
    }

    private static void definition(String name, String effect) {
        given().contentType("application/json").body("{\"properties\": {\"displayName\": \"TLS " + effect
                + "\", \"mode\": \"All\", \"version\": \"1.0.0\", \"policyRule\": " + TLS_RULE.formatted(effect) + "}}")
                .when().put(DEFINITIONS + "/" + name + POLICY_API).then().statusCode(201);
        given().contentType("application/json").body("{\"properties\": {\"displayName\": \"Assign " + effect
                + "\", \"policyDefinitionId\": \"" + DEFINITIONS + "/" + name + "\"}}")
                .when().put(ASSIGNMENTS + "/" + name + "-assign" + POLICY_API).then().statusCode(201);
    }

    private static int storageAccount(String name, String tls, String correlationId) {
        return given().header("x-ms-correlation-request-id", correlationId).contentType("application/json")
                .body("{\"location\": \"eastus\", \"kind\": \"StorageV2\", \"sku\": {\"name\": \"Standard_LRS\"},"
                        + " \"properties\": {\"minimumTlsVersion\": \"" + tls + "\"}}")
                .when().put(RG_SCOPE + "/providers/Microsoft.Storage/storageAccounts/" + name + STORAGE_API)
                .then().extract().statusCode();
    }

    private JsonPath log(String filter) {
        return given().queryParam("api-version", "2015-04-01")
                .queryParam("$filter", "eventTimestamp ge '" + since + "'" + (filter == null ? "" : " and " + filter))
                .when().get(SUB_SCOPE + "/providers/Microsoft.Insights/eventtypes/management/values")
                .then().statusCode(200).extract().jsonPath();
    }

    private static JsonNode policies(JsonPath entry, String path) throws Exception {
        return MAPPER.readTree(entry.getString(path + ".properties.policies"));
    }

    @Test
    void aDenyIsAFailedPolicyEntryAtErrorLevelBesideTheFailedWrite() throws Exception {
        definition("tls-deny", "deny");
        assertEquals(403, storageAccount("sadeny", "TLS1_0", "corr-deny"));
        String resource = RG_SCOPE + "/providers/Microsoft.Storage/storageAccounts/sadeny";

        JsonPath entries = log("correlationId eq 'corr-deny'");
        List<String> categories = entries.getList("value.category.value");
        assertEquals(List.of("Administrative", "Policy", "Administrative"), categories,
                "the write's begin and end entries, and the policy entry between them, share its correlation id");

        JsonPath policy = log("category eq 'Policy'");
        assertEquals(1, policy.getList("value").size());
        String entry = "value[0]";
        assertEquals("Microsoft.Authorization/policies/deny/action", policy.getString(entry + ".operationName.value"));
        assertEquals("EndRequest", policy.getString(entry + ".eventName.value"));
        assertEquals("Error", policy.getString(entry + ".level"));
        assertEquals("Failed", policy.getString(entry + ".status.value"));
        assertEquals(resource, policy.getString(entry + ".resourceId"));
        assertEquals("Microsoft.Storage/storageAccounts", policy.getString(entry + ".resourceType.value"));
        assertEquals("Microsoft.Storage/storageAccounts/write", policy.getString(entry + ".authorization.action"));
        assertEquals(resource, policy.getString(entry + ".authorization.scope"));
        assertEquals("False", policy.getString(entry + ".properties.isComplianceCheck"));
        assertEquals("eastus", policy.getString(entry + ".properties.resourceLocation"));
        assertEquals(MG + "," + TENANT, policy.getString(entry + ".properties.ancestors"),
                "the management groups above the subscription, from its parent to the root");

        JsonNode definition = policies(policy, entry).get(0);
        assertEquals(DEFINITIONS + "/tls-deny", definition.get("policyDefinitionId").asText());
        assertEquals("tls-deny", definition.get("policyDefinitionName").asText());
        assertEquals("TLS deny", definition.get("policyDefinitionDisplayName").asText());
        assertEquals("1.0.0", definition.get("policyDefinitionVersion").asText());
        assertEquals("Deny", definition.get("policyDefinitionEffect").asText());
        assertEquals(ASSIGNMENTS + "/tls-deny-assign", definition.get("policyAssignmentId").asText());
        assertEquals("tls-deny-assign", definition.get("policyAssignmentName").asText());
        assertEquals("Assign deny", definition.get("policyAssignmentDisplayName").asText());
        assertEquals(RG_SCOPE, definition.get("policyAssignmentScope").asText());
        assertTrue(definition.get("policyExemptionIds").isArray());
        assertFalse(definition.has("policySetDefinitionId"), "no initiative assigned");
    }

    @Test
    void anAuditIsASucceededPolicyEntryAtWarningLevelOnceTheWriteSucceeded() throws Exception {
        definition("tls-audit", "audit");
        assertTrue(List.of(200, 201).contains(storageAccount("saaudit", "TLS1_0", "corr-audit")));
        assertTrue(List.of(200, 201).contains(storageAccount("sacompliant", "TLS1_2", "corr-compliant")));

        JsonPath policy = log("category eq 'Policy'");
        assertEquals(1, policy.getList("value").size(), "only the non-compliant write is audited");
        assertEquals("Microsoft.Authorization/policies/audit/action", policy.getString("value[0].operationName.value"));
        assertEquals("Warning", policy.getString("value[0].level"));
        assertEquals("Succeeded", policy.getString("value[0].status.value"));
        assertEquals("corr-audit", policy.getString("value[0].correlationId"));
        assertEquals("Audit", policies(policy, "value[0]").get(0).get("policyDefinitionEffect").asText());
    }

    @Test
    void anAppendLeavesNoPolicyEntry() {
        given().contentType("application/json").body("""
                {"properties": {"mode": "All", "policyRule": {
                  "if": {"field": "type", "equals": "Microsoft.Storage/storageAccounts"},
                  "then": {"effect": "append", "details": [{"field": "tags.env", "value": "prod"}]}}}}""")
                .when().put(DEFINITIONS + "/tag-append" + POLICY_API).then().statusCode(201);
        given().contentType("application/json").body("{\"properties\": {\"policyDefinitionId\": \"" + DEFINITIONS
                + "/tag-append\"}}").when().put(ASSIGNMENTS + "/tag-append" + POLICY_API).then().statusCode(201);
        assertTrue(List.of(200, 201).contains(storageAccount("saappend", "TLS1_2", "corr-append")));

        assertEquals(0, log("category eq 'Policy'").getList("value").size());
        Map<String, Object> end = log("correlationId eq 'corr-append'").getMap("value[0]");
        assertEquals("Administrative", ((Map<?, ?>) end.get("category")).get("value"));
    }
}
