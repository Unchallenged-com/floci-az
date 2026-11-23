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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@DisplayName("Key Vault: management-plane vault operations in the AuditEvent resource log")
class KeyVaultVaultAuditEventTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String API = "?api-version=2023-07-01";
    private static final String TENANT = "00000000-0000-0000-0000-000000000002";
    private static final String SUB = "/subscriptions/00000000-0000-0000-0000-000000000001";
    private static final String RG = SUB + "/resourceGroups/rg-kv-vault-audit";
    private static final String VAULT_NAME = "kvvaultaudit";
    private static final String VAULT = RG + "/providers/Microsoft.KeyVault/vaults/" + VAULT_NAME;
    private static final String VAULT_URI = "https://" + VAULT_NAME + ".vault.azure.net/";
    private static final String WORKSPACE = RG + "/providers/Microsoft.OperationalInsights/workspaces/ws-kv-vault";
    private static final String STORAGE = RG + "/providers/Microsoft.Storage/storageAccounts/sakvvaultaudit";
    private static final String DIAG = "/providers/Microsoft.Insights/diagnosticSettings/";
    private static final String VAULT_BODY = "{\"location\":\"eastus\",\"properties\":{\"tenantId\":\"" + TENANT
        + "\",\"sku\":{\"family\":\"A\",\"name\":\"standard\"}}}";

    private String customerId;

    @BeforeEach
    void reset() {
        given().when().post("/_admin/reset").then().statusCode(204);
        given().contentType("application/json").body("{\"location\": \"eastus\"}")
            .when().put(RG + "?api-version=2021-04-01").then().statusCode(isOneOf(200, 201));
        given().contentType("application/json").body(VAULT_BODY)
            .when().put(VAULT + API).then().statusCode(200);
        customerId = given().contentType("application/json").body("{\"location\": \"eastus\", \"properties\": {}}")
            .when().put(WORKSPACE + "?api-version=2023-09-01").then().statusCode(isOneOf(200, 201))
            .extract().path("properties.customerId");
    }

    private static void setting(String name, String body) {
        given().contentType("application/json").body(body)
            .when().put(VAULT + DIAG + name + "?api-version=2021-05-01-preview").then().statusCode(200);
    }

    private static void storageSetting() {
        setting("to-storage", "{\"properties\": {\"storageAccountId\": \"" + STORAGE
            + "\", \"logs\": [{\"category\": \"AuditEvent\", \"enabled\": true}]}}");
    }

    private static void getVault() {
        given().header("Authorization", "Bearer test-token").header("x-ms-client-request-id", "corr-vault-get")
            .header("User-Agent", "vault-audit-test/1.0")
            .when().get(VAULT + API).then().statusCode(200);
    }

    private static void patchVault() {
        given().header("Authorization", "Bearer test-token").header("x-ms-client-request-id", "corr-vault-patch")
            .contentType("application/json")
            .body("{\"properties\": {\"enableRbacAuthorization\": true, \"enablePurgeProtection\": true,"
                + " \"networkAcls\": {\"bypass\": \"AzureServices\", \"defaultAction\": \"Allow\"}}}")
            .when().patch(VAULT + API).then().statusCode(200);
    }

    /** The records of the storage setting's hourly blob, in the order they were appended. */
    private static List<JsonNode> blobRecords() throws Exception {
        String listing = given().queryParam("restype", "container").queryParam("comp", "list")
            .when().get("/sakvvaultaudit/insights-logs-auditevent").then().statusCode(200).extract().asString();
        String blobName = listing.replaceFirst("(?s).*<Name>(resourceId=[^<]+)</Name>.*", "$1");
        String body = given().when().get("/sakvvaultaudit/insights-logs-auditevent/" + blobName).then()
            .statusCode(200).extract().asString();
        List<JsonNode> records = new ArrayList<>();
        for (String line : body.split("\n")) {
            if (!line.isBlank()) {
                records.add(MAPPER.readTree(line));
            }
        }
        return records;
    }

    private static JsonNode operation(List<JsonNode> records, String operationName) {
        return records.stream().filter(record -> operationName.equals(record.path("operationName").asText()))
            .findFirst().orElseThrow(() -> new AssertionError(operationName + " not in " + records));
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
    void vaultGetIsRecordedWithTheVaultUriAndItsProperties() throws Exception {
        storageSetting();
        getVault();

        JsonNode get = operation(blobRecords(), "VaultGet");
        assertEquals("AuditEvent", get.path("category").asText());
        assertEquals("Success", get.path("resultType").asText());
        assertEquals("OK", get.path("resultSignature").asText());
        assertEquals("corr-vault-get", get.path("correlationId").asText());
        assertEquals("2023-07-01", get.path("operationVersion").asText());
        assertEquals(VAULT.toUpperCase(), get.path("resourceId").asText());
        assertTrue(get.path("durationMs").isTextual(), "durationMs is a string");
        assertTrue(get.path("callerIpAddress").isTextual());
        assertTrue(get.path("identity").path("claim").isObject());

        JsonNode properties = get.path("properties");
        assertEquals(VAULT_URI, properties.path("id").asText());
        assertEquals("vault-audit-test/1.0", properties.path("clientInfo").asText());
        assertEquals(200, properties.path("httpStatusCode").asInt());
        assertTrue(properties.path("httpStatusCode").isInt());
        assertTrue(properties.path("requestUri").asText().endsWith(VAULT + API), properties.toString());
        assertFalse(properties.has("isAccessPolicyMatch"), "a vault operation is no access check");
        assertFalse(properties.has("tlsVersion"));

        JsonNode vault = properties.path("properties");
        assertEquals("A", vault.path("sku").path("Family").asText());
        assertEquals("Standard", vault.path("sku").path("Name").asText());
        assertTrue(vault.path("sku").has("Capacity") && vault.path("sku").path("Capacity").isNull());
        assertEquals(TENANT, vault.path("tenantId").asText());
        assertTrue(vault.has("networkAcls") && vault.path("networkAcls").isNull());
        assertFalse(vault.path("enabledForDeployment").asBoolean(true));
        assertFalse(vault.path("enabledForDiskEncryption").asBoolean(true));
        assertFalse(vault.path("enabledForTemplateDeployment").asBoolean(true));
        assertTrue(vault.path("enableSoftDelete").asBoolean());
        assertEquals(90, vault.path("softDeleteRetentionInDays").asInt());
        assertFalse(vault.path("enableRbacAuthorization").asBoolean(true));
        assertTrue(vault.has("enablePurgeProtection") && vault.path("enablePurgeProtection").isNull());
    }

    @Test
    void vaultPatchCarriesTheVaultAsItIsAfterTheUpdate() throws Exception {
        storageSetting();
        patchVault();

        JsonNode patch = operation(blobRecords(), "VaultPatch");
        assertEquals("corr-vault-patch", patch.path("correlationId").asText());
        assertEquals(VAULT_URI, patch.path("properties").path("id").asText());
        JsonNode vault = patch.path("properties").path("properties");
        assertTrue(vault.path("enableRbacAuthorization").asBoolean());
        assertTrue(vault.path("enablePurgeProtection").asBoolean());
        assertEquals("AzureServices", vault.path("networkAcls").path("bypass").asText());
        assertEquals("Allow", vault.path("networkAcls").path("defaultAction").asText());
        assertEquals(TENANT, vault.path("tenantId").asText());
    }

    @Test
    void vaultPutAndVaultDeleteAreRecordedWithTheVaultUri() throws Exception {
        storageSetting();
        given().contentType("application/json").body(VAULT_BODY)
            .when().put(VAULT + API).then().statusCode(200);
        given().when().delete(VAULT + API).then().statusCode(isOneOf(200, 204));

        List<JsonNode> records = blobRecords();
        JsonNode put = operation(records, "VaultPut");
        assertEquals(VAULT_URI, put.path("properties").path("id").asText());
        assertEquals(200, put.path("properties").path("httpStatusCode").asInt());
        assertEquals("", put.path("correlationId").asText(), "no x-ms-client-request-id was sent");
        JsonNode delete = operation(records, "VaultDelete");
        assertEquals(VAULT_URI, delete.path("properties").path("id").asText());
        assertEquals(VAULT.toUpperCase(), delete.path("resourceId").asText());
        assertTrue(delete.path("properties").path("requestUri").asText().endsWith(VAULT + API));
    }

    @Test
    void aPutWithCreateModeRecoverIsVaultRecover() throws Exception {
        storageSetting();
        given().when().delete(VAULT + API).then().statusCode(isOneOf(200, 204));
        given().contentType("application/json")
            .body("{\"location\":\"eastus\",\"properties\":{\"tenantId\":\"" + TENANT
                + "\",\"sku\":{\"family\":\"A\",\"name\":\"standard\"},\"createMode\":\"recover\"}}")
            .when().put(VAULT + API).then().statusCode(200);

        List<JsonNode> records = blobRecords();
        JsonNode recover = operation(records, "VaultRecover");
        assertEquals(VAULT_URI, recover.path("properties").path("id").asText());
        assertTrue(records.stream().noneMatch(record -> "VaultPut".equals(record.path("operationName").asText())));
    }

    @Test
    void vaultOperationsAreAzureDiagnosticsRowsWithTheVaultPropertiesFlattened() {
        setting("to-workspace", "{\"properties\": {\"workspaceId\": \"" + WORKSPACE
            + "\", \"logs\": [{\"categoryGroup\": \"audit\", \"enabled\": true}]}}");
        patchVault();

        Map<String, Object> row = rows("AzureDiagnostics", "OperationName == 'VaultPatch'").getFirst();
        assertEquals("AuditEvent", row.get("Category"));
        assertEquals("VAULTS", row.get("ResourceType"));
        assertEquals("corr-vault-patch", row.get("CorrelationId"));
        assertEquals(VAULT_URI, row.get("id_s"));
        assertEquals("A", row.get("properties_sku_Family_s"));
        assertEquals("Standard", row.get("properties_sku_Name_s"));
        assertEquals(TENANT, row.get("properties_tenantId_g"));
        assertEquals(Boolean.TRUE, row.get("properties_enableRbacAuthorization_b"));
        assertEquals(Boolean.FALSE, row.get("properties_enabledForDeployment_b"));
        assertEquals("AzureServices", row.get("properties_networkAcls_bypass_s"));
        assertEquals("Allow", row.get("properties_networkAcls_defaultAction_s"));
    }

    @Test
    void aDedicatedSettingWritesTheVaultColumnsOfAzkvAuditLogs() {
        setting("dedicated", "{\"properties\": {\"workspaceId\": \"" + WORKSPACE
            + "\", \"logAnalyticsDestinationType\": \"Dedicated\","
            + " \"logs\": [{\"category\": \"AuditEvent\", \"enabled\": true}]}}");
        patchVault();

        Map<String, Object> row = rows("AZKVAuditLogs", "OperationName == 'VaultPatch'").getFirst();
        assertEquals(VAULT_URI, row.get("Id"));
        assertEquals(Boolean.TRUE, row.get("EnableRbacAuthorization"));
        assertEquals(Boolean.TRUE, row.get("EnablePurgeProtection"));
        assertEquals(Boolean.TRUE, row.get("EnableSoftDelete"));
        assertEquals(Boolean.FALSE, row.get("EnabledForDeployment"));
        assertEquals(Boolean.FALSE, row.get("EnabledForDiskEncryption"));
        assertEquals(Boolean.FALSE, row.get("EnabledForTemplateDeployment"));
        assertEquals(90, ((Number) row.get("SoftDeleteRetentionInDays")).intValue());
        assertEquals("Standard", ((Map<?, ?>) row.get("Sku")).get("Name"));
        assertEquals("Allow", ((Map<?, ?>) row.get("NetworkAcls")).get("defaultAction"));
        assertEquals(200, ((Number) row.get("HttpStatusCode")).intValue());
    }

    @Test
    void aVaultOperationWithoutADiagnosticSettingIsNotDelivered() {
        setting("other", "{\"properties\": {\"workspaceId\": \"" + WORKSPACE
            + "\", \"logs\": [{\"category\": \"AzurePolicyEvaluationDetails\", \"enabled\": true}]}}");
        getVault();
        patchVault();
        assertEquals(0, rows("AzureDiagnostics", null).size());
    }
}
