package io.floci.az.services.blob;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.path.json.JsonPath;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.isOneOf;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@DisplayName("Blob: StorageRead, StorageWrite and StorageDelete resource logs through the blob service's diagnostic settings")
class BlobResourceLogsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SUB = "/subscriptions/00000000-0000-0000-0000-000000000001";
    private static final String RG = SUB + "/resourceGroups/rg-blob-logs";
    private static final String ACCOUNT = "sablobaudit";
    private static final String SINK = "sabloblogsink";
    private static final String BLOB_SERVICE = RG + "/providers/Microsoft.Storage/storageAccounts/" + ACCOUNT
            + "/blobServices/default";
    private static final String WORKSPACE = RG + "/providers/Microsoft.OperationalInsights/workspaces/ws-blob";
    private static final String DIAG = "/providers/Microsoft.Insights/diagnosticSettings/";

    private String customerId;

    @BeforeEach
    void reset() {
        given().when().post("/_admin/reset").then().statusCode(204);
        given().contentType("application/json").body("{\"location\": \"eastus\"}")
                .when().put(RG + "?api-version=2021-04-01").then().statusCode(isOneOf(200, 201));
        for (String account : List.of(ACCOUNT, SINK)) {
            given().contentType("application/json")
                    .body("{\"location\": \"eastus\", \"kind\": \"StorageV2\", \"sku\": {\"name\": \"Standard_LRS\"}}")
                    .when().put(RG + "/providers/Microsoft.Storage/storageAccounts/" + account + "?api-version=2023-01-01")
                    .then().statusCode(isOneOf(200, 201));
        }
        customerId = given().contentType("application/json").body("{\"location\": \"eastus\", \"properties\": {}}")
                .when().put(WORKSPACE + "?api-version=2023-09-01").then().statusCode(isOneOf(200, 201))
                .extract().path("properties.customerId");
    }

    private static void setting(String body) {
        given().contentType("application/json").body(body)
                .when().put(BLOB_SERVICE + DIAG + "blob-logs?api-version=2021-05-01-preview").then().statusCode(200);
    }

    private static RequestSpecification blob(String clientRequestId) {
        return given().header("Authorization", "SharedKey " + ACCOUNT + ":signature")
                .header("x-ms-version", "2024-11-04").header("x-ms-client-request-id", clientRequestId)
                .header("User-Agent", "blob-log-test/1.0");
    }

    private static void blobCalls() {
        blob("c-create").when().put("/" + ACCOUNT + "/docs?restype=container").then().statusCode(201);
        blob("c-put").header("x-ms-blob-type", "BlockBlob").body("patient record")
                .when().put("/" + ACCOUNT + "/docs/record.txt").then().statusCode(201);
        blob("c-get").when().get("/" + ACCOUNT + "/docs/record.txt").then().statusCode(200);
        blob("c-missing").when().get("/" + ACCOUNT + "/docs/absent.txt").then().statusCode(404);
        blob("c-list").when().get("/" + ACCOUNT + "/docs?restype=container&comp=list").then().statusCode(200);
        blob("c-delete").when().delete("/" + ACCOUNT + "/docs/record.txt").then().statusCode(202);
        // An anonymous failure is logged, as exported records show.
        given().header("x-ms-client-request-id", "c-anonymous").when().get("/" + ACCOUNT + "/docs/absent.txt");
    }

    private List<Map<String, Object>> rows(String where) {
        JsonPath result = given().contentType("application/json")
                .body(Map.of("query", "StorageBlobLogs" + (where == null ? "" : " | where " + where)))
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

    private Map<String, Object> only(String clientRequestId) {
        List<Map<String, Object>> rows = rows("ClientRequestId == '" + clientRequestId + "'");
        assertEquals(1, rows.size(), clientRequestId + ": " + rows);
        return rows.getFirst();
    }

    @Test
    void blobRequestsAreStorageBlobLogsRowsWithTheirCategory() {
        setting("{\"properties\": {\"workspaceId\": \"" + WORKSPACE
                + "\", \"logs\": [{\"categoryGroup\": \"allLogs\", \"enabled\": true}]}}");
        blobCalls();

        Map<String, Object> get = only("c-get");
        assertEquals("GetBlob", get.get("OperationName"));
        assertEquals("StorageRead", get.get("Category"));
        assertEquals("200", get.get("StatusCode"), "StorageBlobLogs keeps the status as a string");
        assertEquals("Success", get.get("StatusText"));
        assertEquals("AccountKey", get.get("AuthenticationType"));
        assertEquals("2024-11-04", get.get("OperationVersion"));
        assertEquals("/" + ACCOUNT + "/docs/record.txt", get.get("ObjectKey"));
        assertEquals(ACCOUNT, get.get("AccountName"));
        assertEquals("blob-log-test/1.0", get.get("UserAgentHeader"));
        assertEquals("blob", get.get("ServiceType"));
        assertEquals(BLOB_SERVICE.toLowerCase(), get.get("_ResourceId"));
        assertEquals("StorageBlobLogs", get.get("Type"));
        assertEquals("East US", get.get("Location"), "StorageBlobLogs carries the location's display name");

        assertEquals("StorageWrite", only("c-put").get("Category"));
        assertEquals("PutBlob", only("c-put").get("OperationName"));
        assertEquals("CreateContainer", only("c-create").get("OperationName"));
        assertEquals("ListBlobs", only("c-list").get("OperationName"));
        assertEquals("StorageDelete", only("c-delete").get("Category"));
        assertEquals("DeleteBlob", only("c-delete").get("OperationName"));
        Map<String, Object> missing = only("c-missing");
        assertEquals("404", missing.get("StatusCode"));
        assertEquals("BlobNotFound", missing.get("StatusText"), "a failure carries its error code");
        assertEquals("ClientOtherError", missing.get("MetricResponseType"));
        Map<String, Object> anonymous = only("c-anonymous");
        assertEquals("Anonymous", anonymous.get("AuthenticationType"));
        assertTrue(((Number) get.get("RequestHeaderSize")).longValue() > 0);
        assertTrue(((Number) get.get("ResponseHeaderSize")).longValue() > 0);
    }

    @Test
    void anOAuthRequestCarriesTheHashOfItsTokenAndItsRequester() {
        setting("{\"properties\": {\"workspaceId\": \"" + WORKSPACE
                + "\", \"logs\": [{\"category\": \"StorageWrite\", \"enabled\": true}]}}");
        String token = given().contentType("application/x-www-form-urlencoded").formParam("grant_type", "client_credentials")
                .formParam("client_id", "blob-log-app").formParam("client_secret", "secret")
                .formParam("scope", "https://storage.azure.com/.default")
                .post("/00000000-0000-0000-0000-000000000002/oauth2/v2.0/token").then().statusCode(200)
                .extract().path("access_token");
        given().header("Authorization", "Bearer " + token).header("x-ms-version", "2024-11-04")
                .header("x-ms-client-request-id", "c-oauth")
                .when().put("/" + ACCOUNT + "/oauthdocs?restype=container").then().statusCode(201);

        Map<String, Object> create = only("c-oauth");
        assertEquals("OAuth", create.get("AuthenticationType"));
        assertEquals(BlobResourceLogs.sha256(token), create.get("AuthenticationHash"));
        assertEquals("https://storage.azure.com", create.get("RequesterAudience"));
        assertEquals("00000000-0000-0000-0000-000000000002", create.get("RequesterTenantId"));
    }

    @Test
    void anAccountKeyRequestCarriesTheHashOfTheKeyThatSignedIt() throws Exception {
        setting("{\"properties\": {\"workspaceId\": \"" + WORKSPACE
                + "\", \"logs\": [{\"category\": \"StorageRead\", \"enabled\": true},"
                + " {\"category\": \"StorageWrite\", \"enabled\": true}]}}");
        JsonPath keys = given().when()
                .post(RG + "/providers/Microsoft.Storage/storageAccounts/" + ACCOUNT + "/listKeys?api-version=2023-01-01")
                .then().statusCode(200).extract().jsonPath();
        String key1 = keys.getString("keys[0].value");
        String key2 = keys.getString("keys[1].value");
        blob("c-k-create").when().put("/" + ACCOUNT + "/docs?restype=container").then().statusCode(201);
        blob("c-k-put").header("x-ms-blob-type", "BlockBlob").body("patient record")
                .when().put("/" + ACCOUNT + "/docs/record.txt").then().statusCode(201);

        String date = DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneOffset.UTC).format(Instant.now());
        String stringToSign = "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-client-request-id:c-k-shared\nx-ms-date:" + date
                + "\nx-ms-version:2024-11-04\n/" + ACCOUNT + "/" + ACCOUNT + "/docs\nrestype:container";
        given().header("Authorization", "SharedKey " + ACCOUNT + ":" + hmac(key2, stringToSign))
                .header("x-ms-date", date).header("x-ms-version", "2024-11-04")
                .header("x-ms-client-request-id", "c-k-shared")
                .when().get("/" + ACCOUNT + "/docs?restype=container").then().statusCode(200);

        String expiry = Instant.now().plusSeconds(3600).toString().replaceAll("\\.\\d+Z$", "Z");
        String serviceSig = hmac(key1, "r\n\n" + expiry + "\n/blob/" + ACCOUNT + "/docs/record.txt\n\n\n\n2020-12-06\nb\n\n\n\n\n\n\n");
        given().queryParams(Map.of("sv", "2020-12-06", "sp", "r", "sr", "b", "se", expiry, "sig", serviceSig))
                .header("x-ms-client-request-id", "c-k-sas")
                .when().get("/" + ACCOUNT + "/docs/record.txt").then().statusCode(200);

        String accountSig = hmac(key2, ACCOUNT + "\nr\nb\no\n\n" + expiry + "\n\n\n2022-11-02\n\n");
        given().queryParams(Map.of("sv", "2022-11-02", "ss", "b", "srt", "o", "sp", "r", "se", expiry, "sig", accountSig))
                .header("x-ms-client-request-id", "c-k-account")
                .when().get("/" + ACCOUNT + "/docs/record.txt").then().statusCode(200);

        assertEquals("", only("c-k-create").get("AuthenticationHash"), "a signature no key made names no key");
        assertEquals("AccountKey", only("c-k-shared").get("AuthenticationType"));
        assertEquals("key2(" + BlobResourceLogs.sha256(key2) + ")", only("c-k-shared").get("AuthenticationHash"));
        assertEquals("SAS", only("c-k-sas").get("AuthenticationType"));
        assertEquals("key1(" + BlobResourceLogs.sha256(key1) + "),SasSignature(" + BlobResourceLogs.sha256(serviceSig)
                + ")", only("c-k-sas").get("AuthenticationHash"));
        assertEquals("key2(" + BlobResourceLogs.sha256(key2) + "),SasSignature(" + BlobResourceLogs.sha256(accountSig)
                + ")", only("c-k-account").get("AuthenticationHash"));
    }

    private static String hmac(String key, String stringToSign) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void aStorageSettingAppendsRecordsToTheCategorysContainer() throws Exception {
        String sink = RG + "/providers/Microsoft.Storage/storageAccounts/" + SINK;
        setting("{\"properties\": {\"storageAccountId\": \"" + sink
                + "\", \"logs\": [{\"category\": \"StorageRead\", \"enabled\": true}]}}");
        blobCalls();

        String listing = given().queryParam("restype", "container").queryParam("comp", "list")
                .when().get("/" + SINK + "/insights-logs-storageread").then().statusCode(200).extract().asString();
        String blobName = listing.replaceFirst("(?s).*<Name>(resourceId=[^<]+)</Name>.*", "$1");
        assertTrue(blobName.startsWith("resourceId=" + BLOB_SERVICE + "/y="), "the path keeps the id's case: " + blobName);
        String body = given().when().get("/" + SINK + "/insights-logs-storageread/" + blobName).then().statusCode(200)
                .extract().asString();
        List<JsonNode> records = new ArrayList<>();
        for (String line : body.split("\n")) {
            records.add(MAPPER.readTree(line));
        }
        assertTrue(records.stream().allMatch(r -> "StorageRead".equals(r.path("category").asText())));
        JsonNode get = records.stream().filter(r -> "GetBlob".equals(r.path("operationName").asText())
                && r.path("statusCode").asInt() == 200).findFirst().orElseThrow();
        assertEquals(BLOB_SERVICE, get.path("resourceId").asText());
        assertEquals("1.0", get.path("schemaVersion").asText());
        assertTrue(get.path("statusCode").isInt() && get.path("durationMs").isNumber());
        assertEquals("AccountKey", get.path("identity").path("type").asText());
        assertEquals("c-get", get.path("properties").path("clientRequestId").asText());
        assertEquals("Microsoft.Storage/storageAccounts/blobServices", get.path("resourceType").asText());
        assertFalse(get.path("correlationId").asText().isEmpty());
        assertEquals(404, given().queryParam("restype", "container")
                .when().get("/" + SINK + "/insights-logs-storagewrite").statusCode(), "StorageWrite is not enabled");
    }

    @Test
    void theLogExportsOwnWritesAreNotLogged() {
        // The account logs its own blob service into itself: only the client's requests are logged, not the writes
        // of the log lines, and nothing in the insights-logs- containers.
        String self = RG + "/providers/Microsoft.Storage/storageAccounts/" + ACCOUNT;
        setting("{\"properties\": {\"storageAccountId\": \"" + self + "\", \"workspaceId\": \"" + WORKSPACE
                + "\", \"logs\": [{\"categoryGroup\": \"allLogs\", \"enabled\": true}]}}");
        blobCalls();
        given().queryParam("restype", "container").queryParam("comp", "list")
                .when().get("/" + ACCOUNT + "/insights-logs-storagewrite").then().statusCode(200);

        List<Map<String, Object>> rows = rows(null);
        assertTrue(rows.stream().noneMatch(r -> String.valueOf(r.get("ObjectKey")).startsWith("/" + ACCOUNT + "/insights-logs-")),
                "nothing in the insights-logs- containers is logged");
        assertEquals(7, rows.size(), "the seven client requests, logged once each: " + rows);
    }
}
