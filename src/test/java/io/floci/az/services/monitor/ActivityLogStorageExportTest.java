package io.floci.az.services.monitor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.isOneOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@DisplayName("Monitor: the Activity Log exported through a subscription diagnostic setting to a storage account")
class ActivityLogStorageExportTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SUB_ID = "00000000-0000-0000-0000-00000000abcd";
    private static final String SUB = "/subscriptions/" + SUB_ID;
    private static final String RG = SUB + "/resourceGroups/rg-blob-export";
    private static final String ACCOUNT = "saactivitylog";
    private static final String SA = RG + "/providers/Microsoft.Storage/storageAccounts/" + ACCOUNT;
    private static final String SETTING = SUB + "/providers/Microsoft.Insights/diagnosticSettings/to-storage";

    @BeforeEach
    void reset() {
        given().when().post("/_admin/reset").then().statusCode(204);
        given().contentType("application/json").body("{\"location\": \"eastus\"}")
                .when().put(RG + "?api-version=2021-04-01").then().statusCode(isOneOf(200, 201));
    }

    private static void setting(String category) {
        given().contentType("application/json")
                .body("{\"properties\": {\"storageAccountId\": \"" + SA + "\", \"logs\": [{\"category\": \"" + category
                        + "\", \"enabled\": true}]}}")
                .when().put(SETTING + "?api-version=2021-05-01-preview").then().statusCode(200);
    }

    private static void write(String name, String correlationId) {
        given().header("x-ms-correlation-request-id", correlationId).contentType("application/json")
                .body("{\"location\": \"eastus\", \"kind\": \"StorageV2\", \"sku\": {\"name\": \"Standard_LRS\"}}")
                .when().put(RG + "/providers/Microsoft.Storage/storageAccounts/" + name + "?api-version=2023-01-01")
                .then().statusCode(isOneOf(200, 201));
    }

    private static List<JsonNode> lines(String body) throws Exception {
        List<JsonNode> out = new ArrayList<>();
        for (String line : body.split("\n")) {
            if (!line.isBlank()) {
                out.add(MAPPER.readTree(line));
            }
        }
        return out;
    }

    @Test
    void entriesAreAppendedAsJsonLinesToTheHourlyAppendBlob() throws Exception {
        setting("Administrative");
        // The account the setting writes to, created first: its own write is exported too.
        write(ACCOUNT, "corr-account");
        write("sablobtarget", "corr-target");

        String hourPrefix = ActivityLogStorageExport.blobName(SUB_ID, Instant.now());
        assertTrue(hourPrefix.startsWith("resourceId=/SUBSCRIPTIONS/00000000-0000-0000-0000-00000000ABCD/y="),
                "the subscription id is uppercased in the path: " + hourPrefix);
        assertTrue(hourPrefix.endsWith("/m=00/PT1H.json"));

        String listing = given().queryParam("restype", "container").queryParam("comp", "list")
                .when().get("/" + ACCOUNT + "/" + ActivityLogStorageExport.CONTAINER).then().statusCode(200)
                .extract().asString();
        assertTrue(listing.contains("<Name>resourceId=/SUBSCRIPTIONS/" + SUB_ID.toUpperCase()), listing);
        assertTrue(listing.contains("AppendBlob"), "the blob is an append blob: " + listing);
        String blobName = listing.replaceFirst("(?s).*<Name>(resourceId=[^<]+)</Name>.*", "$1");

        Response blob = given().when().get("/" + ACCOUNT + "/" + ActivityLogStorageExport.CONTAINER + "/" + blobName);
        assertEquals(200, blob.statusCode());
        assertEquals("AppendBlob", blob.header("x-ms-blob-type"));
        List<JsonNode> records = lines(blob.asString());
        List<JsonNode> target = records.stream()
                .filter(r -> "corr-target".equals(r.path("correlationId").asText())).toList();
        assertEquals(2, target.size(), "one line per entry, the start and the success");
        JsonNode success = target.stream().filter(r -> "Success".equals(r.path("resultType").asText())).findFirst()
                .orElseThrow();
        assertEquals("MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE", success.path("operationName").asText());
        assertEquals((RG + "/providers/Microsoft.Storage/storageAccounts/sablobtarget").toUpperCase(),
                success.path("resourceId").asText());
        assertEquals("Administrative", success.path("category").asText());
        assertTrue(success.path("properties").has("hierarchy"));
        assertTrue(!blob.asString().startsWith("{\"records\""), "no records wrapper");
    }

    @Test
    void aSettingThatDoesNotTakeTheCategoryWritesNothing() {
        setting("Policy");
        write("sanothing", "corr-nothing");
        given().queryParam("restype", "container")
                .when().get("/" + ACCOUNT + "/" + ActivityLogStorageExport.CONTAINER).then().statusCode(404);
    }
}
