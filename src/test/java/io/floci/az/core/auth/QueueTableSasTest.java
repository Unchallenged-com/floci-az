package io.floci.az.core.auth;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code parity-overrides.strict-storage-keys} on the Queue and Table services: a service SAS is signed over the
 * service's string to sign, every SAS must hold the operation's permission, and {@code sip} and {@code spr} are
 * checked on every SAS, Blob's included. SAS are signed here as Create a service SAS and Create an account SAS
 * describe them.
 */
@QuarkusTest
// The same profile as StrictStorageKeysTest, so the suite starts no other application for it.
@TestProfile(StrictStorageKeysTest.Strict.class)
@DisplayName("Storage: Queue and Table SAS signatures, permissions, sip and spr under strict-storage-keys")
class QueueTableSasTest {

    private static final String ARM = "/subscriptions/sub-qt-sas/resourceGroups/rg-qt-sas"
            + "/providers/Microsoft.Storage/storageAccounts/";
    private static final String API = "?api-version=2025-08-01";
    private static final String VERSION = "2022-11-02";
    private static final String WRONG_KEY = Base64.getEncoder().encodeToString(new byte[64]);

    @Test
    void aQueueServiceSasGrantsItsPermissionsOnItsQueueOnly() throws Exception {
        String account = "qtsasqueueacct";
        String key = createAccount(account);
        String queue = "/" + account + "-queue/orders";
        given().put(queue).then().statusCode(201);
        String body = "<QueueMessage><MessageText>hello</MessageText></QueueMessage>";

        given().queryParams(queueSas(account, "orders", "raup", null, key)).body(body)
                .post(queue + "/messages").then().statusCode(201);
        given().queryParams(queueSas(account, "orders", "raup", null, key)).queryParam("peekonly", "true")
                .get(queue + "/messages").then().statusCode(200).body(containsString("hello"));
        refused(given().queryParams(queueSas(account, "orders", "r", null, key)).body(body)
                .post(queue + "/messages"), "AuthorizationPermissionMismatch");
        refused(given().queryParams(queueSas(account, "orders", "raup", null, WRONG_KEY)).body(body)
                .post(queue + "/messages"), "AuthenticationFailed")
                .then().body(containsString("Signature did not match. String to sign used was raup\n\n"));
        refused(given().queryParams(queueSas(account, "orders", "raup", null, key)).body(body)
                .post("/" + account + "-queue/other/messages"), "AuthenticationFailed");
        refused(given().queryParams(queueSas(account, "orders", "raup", null, key))
                .delete(queue + "/messages"), "AuthorizationFailure");
        refused(given().queryParams(queueSas(account, "created", "raup", null, key))
                .put("/" + account + "-queue/created"), "AuthorizationFailure");
    }

    @Test
    void anAccountSasToTheQueueServiceNeedsItsServiceResourceTypeAndPermission() throws Exception {
        String account = "qtsasaccountacct";
        String key = createAccount(account);
        String queue = "/" + account + "-queue/jobs";
        given().put(queue).then().statusCode(201);
        String body = "<QueueMessage><MessageText>job</MessageText></QueueMessage>";

        given().queryParams(accountSas(account, "q", "o", "a", null, key)).body(body)
                .post(queue + "/messages").then().statusCode(201);
        refused(given().queryParams(accountSas(account, "b", "o", "a", null, key)).body(body)
                .post(queue + "/messages"), "AuthorizationServiceMismatch");
        refused(given().queryParams(accountSas(account, "q", "o", "c", null, key))
                .put("/" + account + "-queue/made"), "AuthorizationResourceTypeMismatch");
        given().queryParams(accountSas(account, "q", "c", "c", null, key))
                .put("/" + account + "-queue/made").then().statusCode(201);
        refused(given().queryParams(accountSas(account, "q", "o", "r", null, key)).body(body)
                .post(queue + "/messages"), "AuthorizationPermissionMismatch");
    }

    @Test
    void sipAndSprAreCheckedOnEverySas() throws Exception {
        String account = "qtsasipacct";
        String key = createAccount(account);
        // An IPv4 loopback caller, whatever localhost resolves to.
        String base = "http://127.0.0.1:" + RestAssured.port;
        String queue = base + "/" + account + "-queue/scoped";
        given().put(queue).then().statusCode(201);

        Map<String, String> elsewhere = accountSas(account, "q", "c", "r", "203.0.113.10-203.0.113.20", key);
        refused(given().queryParams(elsewhere).queryParam("comp", "metadata").get(queue),
                "AuthorizationSourceIPMismatch")
                .then().body(containsString("using this source IP 127.0.0.1."));
        given().queryParams(accountSas(account, "q", "c", "r", "127.0.0.1", key)).queryParam("comp", "metadata")
                .get(queue).then().statusCode(200);
        Map<String, String> httpsOnly = accountSas(account, "q", "c", "r", null, key);
        httpsOnly.put("spr", "https");
        httpsOnly.put("sig", hmac(key, account + "\nr\nq\nc\n\n" + httpsOnly.get("se") + "\n\nhttps\n" + VERSION
                + "\n\n"));
        refused(given().queryParams(httpsOnly).queryParam("comp", "metadata").get(queue),
                "AuthorizationProtocolMismatch");

        given().put(base + "/" + account + "/scoped?restype=container").then().statusCode(201);
        refused(given().queryParams(accountSas(account, "b", "c", "l", "203.0.113.10", key))
                .queryParam("restype", "container").queryParam("comp", "list")
                .get(base + "/" + account + "/scoped"), "AuthorizationSourceIPMismatch");
    }

    @Test
    void aTableServiceSasGrantsItsPermissionsOnItsTable() throws Exception {
        String account = "qtsastableacct";
        String key = createAccount(account);
        String tables = "/" + account + "-table/Tables";
        given().contentType("application/json").body("{\"TableName\":\"Orders\"}").post(tables)
                .then().statusCode(201);
        String entity = "{\"PartitionKey\":\"p1\",\"RowKey\":\"r1\",\"Total\":3}";

        table(tableSas(account, "Orders", "raud", key)).body(entity)
                .post("/" + account + "-table/Orders").then().statusCode(201);
        table(tableSas(account, "Orders", "raud", key))
                .get("/" + account + "-table/Orders()").then().statusCode(200).body(containsString("Total"));
        refused(table(tableSas(account, "Orders", "r", key)).body(entity.replace("r1", "r2"))
                .post("/" + account + "-table/Orders"), "AuthorizationPermissionMismatch")
                .then().body(containsString("\"odata.error\""));
        refused(table(tableSas(account, "Orders", "u", key)).body(entity)
                .put("/" + account + "-table/Orders(PartitionKey='p1',RowKey='r3')"), "AuthorizationPermissionMismatch");
        table(tableSas(account, "Orders", "au", key)).body(entity)
                .put("/" + account + "-table/Orders(PartitionKey='p1',RowKey='r3')").then().statusCode(204);
        table(tableSas(account, "Orders", "u", key)).header("If-Match", "*").body(entity)
                .put("/" + account + "-table/Orders(PartitionKey='p1',RowKey='r3')").then().statusCode(204);
        refused(table(tableSas(account, "Orders", "raud", WRONG_KEY))
                .get("/" + account + "-table/Orders()"), "AuthenticationFailed");
        given().contentType("application/json").body("{\"TableName\":\"Other\"}").post(tables).then().statusCode(201);
        refused(table(tableSas(account, "Orders", "raud", key))
                .get("/" + account + "-table/Other()"), "AuthorizationFailure");
        refused(table(tableSas(account, "Orders", "raud", key)).body("{\"TableName\":\"Made\"}")
                .post(tables), "AuthorizationFailure");
    }

    private static RequestSpecification table(Map<String, String> sas) {
        return given().queryParams(sas).contentType("application/json")
                .header("Accept", "application/json;odata=nometadata");
    }

    private static Response refused(Response response, String code) {
        response.then().statusCode(403).header("x-ms-error-code", code)
                .body(containsString("RequestId:" + response.getHeader("x-ms-request-id")));
        return response;
    }

    private static String createAccount(String account) {
        given().contentType("application/json").body("{\"location\":\"eastus\"}")
            .when().put(ARM + account + API).then().statusCode(200);
        return given().when().post(ARM + account + "/listKeys" + API).then().statusCode(200)
                .extract().path("keys[1].value");
    }

    private static String expiry() {
        return Instant.now().plusSeconds(3600).toString().replaceAll("\\.\\d+Z$", "Z");
    }

    /** Queue service SAS, 2015-04-05 and later: sp st se /queue/account/queue si sip spr sv. */
    private static Map<String, String> queueSas(String account, String queue, String permissions, String ip,
                                                String key) throws Exception {
        String se = expiry();
        String fields = permissions + "\n\n" + se + "\n/queue/" + account + "/" + queue + "\n\n" + (ip == null ? "" : ip)
                + "\n\n" + VERSION;
        Map<String, String> query = new LinkedHashMap<>(Map.of("sv", VERSION, "sp", permissions, "se", se));
        if (ip != null) {
            query.put("sip", ip);
        }
        query.put("sig", hmac(key, fields));
        return query;
    }

    /** Table service SAS: sp st se /table/account/table si sip spr sv spk srk epk erk, the table lowercase. */
    private static Map<String, String> tableSas(String account, String table, String permissions, String key)
            throws Exception {
        String se = expiry();
        String fields = permissions + "\n\n" + se + "\n/table/" + account + "/" + table.toLowerCase() + "\n\n\n\n"
                + VERSION + "\n\n\n\n";
        Map<String, String> query = new LinkedHashMap<>(Map.of("sv", VERSION, "sp", permissions, "se", se,
                "tn", table));
        query.put("sig", hmac(key, fields));
        return query;
    }

    /** Account SAS, 2020-12-06 and later. */
    private static Map<String, String> accountSas(String account, String services, String types, String permissions,
                                                  String ip, String key) throws Exception {
        String se = expiry();
        String fields = account + "\n" + permissions + "\n" + services + "\n" + types + "\n\n" + se + "\n"
                + (ip == null ? "" : ip) + "\nhttps,http\n" + VERSION + "\n\n";
        Map<String, String> query = new LinkedHashMap<>(Map.of("sv", VERSION, "ss", services, "srt", types,
                "sp", permissions, "se", se, "spr", "https,http"));
        if (ip != null) {
            query.put("sip", ip);
        }
        query.put("sig", hmac(key, fields));
        return query;
    }

    private static String hmac(String key, String fields) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(fields.getBytes(StandardCharsets.UTF_8)));
    }
}
