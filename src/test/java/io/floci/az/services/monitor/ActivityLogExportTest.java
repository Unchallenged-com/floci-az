package io.floci.az.services.monitor;

import io.floci.az.services.entra.EntraStore;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@DisplayName("Monitor: the Activity Log exported through a subscription diagnostic setting to a Log Analytics workspace")
class ActivityLogExportTest {

    private static final String TENANT = "00000000-0000-0000-0000-000000000002";
    private static final String SUB_ID = "00000000-0000-0000-0000-000000000001";
    private static final String SUB = "/subscriptions/" + SUB_ID;
    private static final String RG = SUB + "/resourceGroups/rg-Export";
    private static final String WORKSPACE = RG + "/providers/Microsoft.OperationalInsights/workspaces/ws-export";
    private static final String SA = RG + "/providers/Microsoft.Storage/storageAccounts/saexport";
    private static final String SETTING = SUB + "/providers/Microsoft.Insights/diagnosticSettings/activity";
    private static final String API = "?api-version=2021-05-01-preview";

    private String customerId;

    @BeforeEach
    void reset() {
        given().when().post("/_admin/reset").then().statusCode(204);
        given().contentType("application/json").body("{\"location\": \"eastus\"}")
                .when().put(RG + "?api-version=2021-04-01").then().statusCode(isOneOf(200, 201));
        customerId = given().contentType("application/json").body("{\"location\": \"eastus\", \"properties\": {}}")
                .when().put(WORKSPACE + "?api-version=2023-09-01").then().statusCode(isOneOf(200, 201))
                .extract().path("properties.customerId");
    }

    private static void setting(String logs) {
        given().contentType("application/json")
                .body("{\"properties\": {\"workspaceId\": \"" + WORKSPACE + "\", \"logs\": " + logs + "}}")
                .when().put(SETTING + API).then().statusCode(200);
    }

    private static String token() {
        return given().contentType("application/x-www-form-urlencoded").formParam("grant_type", "client_credentials")
                .formParam("client_id", EntraStore.DEV_CLIENT_ID).formParam("client_secret", EntraStore.DEV_CLIENT_SECRET)
                .formParam("scope", "https://management.azure.com/.default")
                .post("/" + TENANT + "/oauth2/v2.0/token").then().statusCode(200).extract().path("access_token");
    }

    private static void storageAccount(String correlationId) {
        given().header("Authorization", "Bearer " + token()).header("x-ms-correlation-request-id", correlationId)
                .contentType("application/json")
                .body("{\"location\": \"eastus\", \"kind\": \"StorageV2\", \"sku\": {\"name\": \"Standard_LRS\"}}")
                .when().put(SA + "?api-version=2023-01-01").then().statusCode(isOneOf(200, 201));
    }

    /** The AzureActivity rows of the workspace, as the query API answers them, one map per row. */
    private List<Map<String, Object>> rows(String where) {
        JsonPath result = given().contentType("application/json")
                .body(Map.of("query", "AzureActivity" + (where == null ? "" : " | where " + where)))
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
    @SuppressWarnings("unchecked")
    void anAdministrativeWriteBecomesAzureActivityRowsInTheWorkspace() {
        setting("[{\"category\": \"Administrative\", \"enabled\": true}]");
        storageAccount("corr-export");

        List<Map<String, Object>> rows = rows("CorrelationId == 'corr-export'");
        assertEquals(2, rows.size(), "the write's start and its success");
        Map<String, Object> start = rows.stream().filter(r -> "Start".equals(r.get("ActivityStatusValue"))).findFirst().orElseThrow();
        Map<String, Object> success = rows.stream().filter(r -> "Success".equals(r.get("ActivityStatusValue"))).findFirst().orElseThrow();

        assertEquals("MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE", success.get("OperationNameValue"));
        assertEquals("Administrative", success.get("CategoryValue"));
        assertEquals("Information", success.get("Level"));
        assertTrue(List.of("OK", "Created").contains(success.get("ActivitySubstatusValue")));
        assertEquals("", start.get("ActivitySubstatusValue"));
        assertEquals("MICROSOFT.STORAGE", success.get("ResourceProviderValue"));
        assertEquals("RG-EXPORT", success.get("ResourceGroup"));
        assertEquals(SUB_ID, success.get("SubscriptionId"));
        assertEquals(SA.toLowerCase(), success.get("_ResourceId"));
        assertEquals(TENANT + "/" + SUB_ID, success.get("Hierarchy"));
        assertEquals(customerId, success.get("TenantId"));
        assertEquals("Azure", success.get("SourceSystem"));
        assertEquals("AzureActivity", success.get("Type"));
        assertEquals(EntraStore.DEV_SP_OBJECT_ID, success.get("Caller"));
        assertEquals("", success.get("OperationName"), "the deprecated columns stay empty");
        assertEquals(success.get("EventSubmissionTimestamp"), success.get("TimeGenerated"));
        Map<String, Object> authorization = (Map<String, Object>) success.get("Authorization_d");
        assertEquals("Microsoft.Storage/storageAccounts/write", authorization.get("action"));
        assertEquals(SA, authorization.get("scope"));
        assertTrue(((String) success.get("Authorization")).contains("Microsoft.Storage/storageAccounts/write"));
        Map<String, Object> properties = (Map<String, Object>) success.get("Properties_d");
        assertEquals("Administrative", properties.get("eventCategory"));
        assertEquals(SA, properties.get("entity"));
        assertEquals("Microsoft.Storage/storageAccounts/write", properties.get("message"));
        assertEquals("saexport", properties.get("resource"));
        assertEquals("Success", properties.get("activityStatusValue"));
    }

    @Test
    void onlyTheCategoriesTheSettingEnablesAreExported() {
        setting("[{\"category\": \"Policy\", \"enabled\": true}, {\"category\": \"Administrative\", \"enabled\": false}]");
        storageAccount("corr-not-exported");
        assertEquals(0, rows("CorrelationId == 'corr-not-exported'").size());

        setting("[{\"categoryGroup\": \"allLogs\", \"enabled\": true}]");
        storageAccount("corr-all-logs");
        assertEquals(2, rows("CorrelationId == 'corr-all-logs'").size(), "allLogs takes every category");
    }

    @Test
    void entriesOfAnotherSubscriptionOrBeforeTheSettingAreNotExported() {
        storageAccount("corr-before");
        setting("[{\"category\": \"Administrative\", \"enabled\": true}]");
        given().contentType("application/json").body("{\"location\": \"eastus\"}")
                .when().put("/subscriptions/00000000-0000-0000-0000-0000000000aa/resourceGroups/rg-other?api-version=2021-04-01")
                .then().statusCode(isOneOf(200, 201));

        assertEquals(0, rows("CorrelationId == 'corr-before'").size());
        assertEquals(0, rows("SubscriptionId == '00000000-0000-0000-0000-0000000000aa'").size());
    }
}
