package io.floci.az.services.keyvault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.isOneOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@DisplayName("Key Vault: the AuditEvent resource log, delivered through the vault's diagnostic settings")
class KeyVaultAuditEventTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SUB = "/subscriptions/00000000-0000-0000-0000-000000000001";
    private static final String RG = SUB + "/resourceGroups/rg-kv-audit";
    private static final String VAULT_NAME = "kvaudit";
    private static final String VAULT = RG + "/providers/Microsoft.KeyVault/vaults/" + VAULT_NAME;
    private static final String WORKSPACE = RG + "/providers/Microsoft.OperationalInsights/workspaces/ws-kv";
    private static final String STORAGE = RG + "/providers/Microsoft.Storage/storageAccounts/sakvaudit";
    private static final String DATA = "/" + VAULT_NAME + "-keyvault/";
    private static final String DIAG = "/providers/Microsoft.Insights/diagnosticSettings/";

    private String customerId;

    @BeforeEach
    void reset() {
        given().when().post("/_admin/reset").then().statusCode(204);
        given().contentType("application/json").body("{\"location\": \"eastus\"}")
                .when().put(RG + "?api-version=2021-04-01").then().statusCode(isOneOf(200, 201));
        given().contentType("application/json").body("{\"location\":\"eastus\",\"properties\":{\"tenantId\":"
                        + "\"00000000-0000-0000-0000-000000000002\",\"sku\":{\"family\":\"A\",\"name\":\"standard\"}}}")
                .when().put(VAULT + "?api-version=2023-07-01").then().statusCode(isOneOf(200, 201));
        customerId = given().contentType("application/json").body("{\"location\": \"eastus\", \"properties\": {}}")
                .when().put(WORKSPACE + "?api-version=2023-09-01").then().statusCode(isOneOf(200, 201))
                .extract().path("properties.customerId");
    }

    private static void setting(String name, String body) {
        given().contentType("application/json").body(body)
                .when().put(VAULT + DIAG + name + "?api-version=2021-05-01-preview").then().statusCode(200);
    }

    private static void secretCalls() {
        given().header("Authorization", "Bearer test-token").header("x-ms-client-request-id", "corr-set")
                .contentType("application/json").body("{\"value\": \"s3cret\"}")
                .when().put(DATA + "secrets/db-password?api-version=7.4").then().statusCode(200);
        given().header("Authorization", "Bearer test-token").header("x-ms-client-request-id", "corr-get")
                .header("User-Agent", "audit-test/1.0")
                .when().get(DATA + "secrets/db-password?api-version=7.4").then().statusCode(200);
        given().header("Authorization", "Bearer test-token").header("x-ms-client-request-id", "corr-missing")
                .when().get(DATA + "secrets/absent?api-version=7.4").then().statusCode(404);
        given().header("x-ms-client-request-id", "corr-challenge")
                .when().get(DATA + "secrets/db-password?api-version=7.4").then().statusCode(401);
        given().header("Authorization", "Bearer test-token").header("x-ms-client-request-id", "corr-list")
                .when().get(DATA + "secrets?api-version=7.4").then().statusCode(200);
    }

    private List<Map<String, Object>> rows(String table, String where) {
        JsonPath result = given().contentType("application/json")
                .body(Map.of("query", table + (where == null ? "" : " | where " + where)))
                .when().post("/v1/workspaces/" + customerId + "/query").then().statusCode(200).extract().jsonPath();
        List<String> columns = result.getList("tables[0].columns.name");
        List<List<Object>> values = result.getList("tables[0].rows");
        List<Map<String, Object>> out = new ArrayList<>();
        for (List<Object> row : values) {
            Map<String, Object> map = new LinkedHashMap<>();
            for (int i = 0; i < columns.size(); i++) {
                map.put(columns.get(i), row.get(i));
            }
            out.add(map);
        }
        return out;
    }

    @Test
    void secretOperationsAreAzureDiagnosticsRowsInTheWorkspace() {
        setting("to-workspace", "{\"properties\": {\"workspaceId\": \"" + WORKSPACE
                + "\", \"logs\": [{\"category\": \"AuditEvent\", \"enabled\": true}]}}");
        secretCalls();

        Map<String, Object> get = rows("AzureDiagnostics", "CorrelationId == 'corr-get'").getFirst();
        assertEquals("SecretGet", get.get("OperationName"));
        assertEquals("AuditEvent", get.get("Category"));
        assertEquals("Success", get.get("ResultType"));
        assertEquals("OK", get.get("ResultSignature"));
        assertEquals("7.4", get.get("OperationVersion"));
        assertEquals("MICROSOFT.KEYVAULT", get.get("ResourceProvider"));
        assertEquals("VAULTS", get.get("ResourceType"));
        assertEquals("KVAUDIT", get.get("Resource"));
        assertEquals("RG-KV-AUDIT", get.get("ResourceGroup"));
        assertEquals(VAULT.toUpperCase(), get.get("ResourceId"));
        assertEquals(VAULT.toLowerCase(), get.get("_ResourceId"));
        assertEquals("audit-test/1.0", get.get("clientInfo_s"));
        assertEquals(200.0, ((Number) get.get("httpStatusCode_d")).doubleValue());
        assertTrue(((String) get.get("requestUri_s")).endsWith("/secrets/db-password?api-version=7.4"));
        assertTrue(((String) get.get("id_s")).endsWith("/secrets/db-password"));
        assertEquals(Boolean.TRUE, get.get("isAccessPolicyMatch_b"), "an access-policy vault");
        assertEquals("AzureDiagnostics", get.get("Type"));

        Map<String, Object> missing = rows("AzureDiagnostics", "CorrelationId == 'corr-missing'").getFirst();
        assertEquals("SecretGet", missing.get("OperationName"));
        assertEquals("Success", missing.get("ResultType"), "Key Vault writes Success whatever the status");
        assertEquals("Not Found", missing.get("ResultSignature"));
        assertNotNull(missing.get("ResultDescription"));

        Map<String, Object> challenge = rows("AzureDiagnostics", "CorrelationId == 'corr-challenge'").getFirst();
        assertEquals("Authentication", challenge.get("OperationName"));
        assertEquals("Unauthorized", challenge.get("ResultSignature"));

        Map<String, Object> list = rows("AzureDiagnostics", "CorrelationId == 'corr-list'").getFirst();
        assertEquals("SecretList", list.get("OperationName"));
        assertNull(list.get("id_s"), "a listing names no object");
        assertEquals("SecretSet", rows("AzureDiagnostics", "CorrelationId == 'corr-set'").getFirst().get("OperationName"));
    }

    @Test
    void aListIsOneAzureDiagnosticsColumnHoldingItsJson() {
        setting("to-workspace", "{\"properties\": {\"workspaceId\": \"" + WORKSPACE
                + "\", \"logs\": [{\"category\": \"AuditEvent\", \"enabled\": true}]}}");
        given().header("Authorization", "Bearer test-token").contentType("application/json")
                .body("{\"kty\": \"EC\", \"crv\": \"P-256\", \"key_ops\": [\"sign\", \"verify\"]}")
                .when().post(DATA + "keys/signing/create?api-version=7.4").then().statusCode(200);
        given().header("Authorization", "Bearer test-token").header("x-ms-client-request-id", "corr-key-update")
                .contentType("application/json").body("{\"attributes\": {\"enabled\": false}}")
                .when().patch(DATA + "keys/signing?api-version=7.4").then().statusCode(200);

        Map<String, Object> update = rows("AzureDiagnostics", "CorrelationId == 'corr-key-update'").getFirst();
        assertEquals("KeyUpdate", update.get("OperationName"));
        assertEquals("[\"sign\",\"verify\"]", update.get("keyProperties_operations_s"));
        assertEquals(Boolean.FALSE, update.get("keyProperties_attributes_enabled_b"));
    }

    @Test
    void aDedicatedSettingWritesAzkvAuditLogsRows() {
        setting("dedicated", "{\"properties\": {\"workspaceId\": \"" + WORKSPACE
                + "\", \"logAnalyticsDestinationType\": \"Dedicated\","
                + " \"logs\": [{\"categoryGroup\": \"audit\", \"enabled\": true}]}}");
        secretCalls();

        assertEquals(0, rows("AzureDiagnostics", null).size());
        Map<String, Object> get = rows("AZKVAuditLogs", "CorrelationId == 'corr-get'").getFirst();
        assertEquals("SecretGet", get.get("OperationName"));
        assertEquals("OK", get.get("ResultSignature"));
        assertEquals(200, ((Number) get.get("HttpStatusCode")).intValue());
        assertEquals("audit-test/1.0", get.get("ClientInfo"));
        assertEquals(customerId, get.get("TenantId"));
        assertEquals("AZKVAuditLogs", get.get("Type"));
    }

    @Test
    void aStorageSettingAppendsTheRecordsToTheHourlyBlob() throws Exception {
        setting("to-storage", "{\"properties\": {\"storageAccountId\": \"" + STORAGE
                + "\", \"logs\": [{\"category\": \"AuditEvent\", \"enabled\": true}]}}");
        secretCalls();

        String listing = given().queryParam("restype", "container").queryParam("comp", "list")
                .when().get("/sakvaudit/insights-logs-auditevent").then().statusCode(200).extract().asString();
        String blobName = listing.replaceFirst("(?s).*<Name>(resourceId=[^<]+)</Name>.*", "$1");
        assertTrue(blobName.startsWith("resourceId=" + VAULT.toUpperCase() + "/y="), blobName);
        String body = given().when().get("/sakvaudit/insights-logs-auditevent/" + blobName).then().statusCode(200)
                .extract().asString();
        JsonNode get = null;
        for (String line : body.split("\n")) {
            JsonNode record = MAPPER.readTree(line);
            if ("corr-get".equals(record.path("correlationId").asText())) {
                get = record;
            }
        }
        assertTrue(get != null, body);
        assertEquals("SecretGet", get.path("operationName").asText());
        assertEquals("AuditEvent", get.path("category").asText());
        assertEquals(VAULT.toUpperCase(), get.path("resourceId").asText());
        assertTrue(get.path("durationMs").isTextual(), "durationMs is a string");
        assertTrue(get.path("properties").path("httpStatusCode").isInt());
        assertTrue(get.path("identity").path("claim").isObject());
    }

    @Test
    void aSettingWithoutTheCategoryGetsNothing() {
        setting("other", "{\"properties\": {\"workspaceId\": \"" + WORKSPACE
                + "\", \"logs\": [{\"category\": \"AzurePolicyEvaluationDetails\", \"enabled\": true}]}}");
        secretCalls();
        assertEquals(0, rows("AzureDiagnostics", null).size());
    }
}
