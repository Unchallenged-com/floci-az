package io.floci.az.core.auth;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
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
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Stored access policies: Set and Get Container ACL keep a container's policies, and a service SAS that names one
 * ({@code si}) on a container, a queue or a table takes the start, expiry and permissions the policy holds, so
 * changing or removing the policy changes or revokes every SAS that names it. SAS are signed here as Create a service
 * SAS describes them.
 */
@QuarkusTest
// The same profile as StrictStorageKeysTest, so the suite starts no other application for it.
@TestProfile(StrictStorageKeysTest.Strict.class)
@DisplayName("Storage: stored access policies and the SAS that name them")
class StoredAccessPolicyTest {

    private static final String ARM = "/subscriptions/sub-sap/resourceGroups/rg-sap"
            + "/providers/Microsoft.Storage/storageAccounts/";
    private static final String API = "?api-version=2025-08-01";
    private static final String VERSION = "2022-11-02";
    private static final String NOT_FOUND = "SAS identifier cannot be found for specified signed identifier";

    @Test
    void setContainerAclStoresThePoliciesAndThePublicAccessLevelThatGetContainerAclReturns() {
        String account = "sapcontaineracl";
        createAccount(account);
        String container = "/" + account + "/reports";
        String created = given().queryParam("restype", "container").put(container)
                .then().statusCode(201).extract().header("ETag");

        String etag = containerAcl(given()).header("x-ms-blob-public-access", "blob")
                .body(identifiers(policy("reader", past(), future(), "rl"), policy("revoked", null, null, null)))
                .put(container).then().statusCode(200)
                .header("Last-Modified", notNullValue()).extract().header("ETag");
        assertNotEquals(created, etag);
        containerAcl(given()).get(container).then().statusCode(200)
                .header("ETag", etag)
                .header("x-ms-blob-public-access", "blob")
                .body(containsString("<Id>reader</Id>"))
                .body(containsString("<Permission>rl</Permission>"))
                .body(containsString("<SignedIdentifier><Id>revoked</Id></SignedIdentifier>"));

        containerAcl(given()).put(container).then().statusCode(200);
        containerAcl(given()).get(container).then().statusCode(200)
                .header("x-ms-blob-public-access", nullValue())
                .body(not(containsString("<SignedIdentifier>")));

        containerAcl(given()).header("x-ms-blob-public-access", "everyone").put(container)
                .then().statusCode(400).header("x-ms-error-code", "InvalidHeaderValue");
        containerAcl(given()).body(identifiers(policy("p1", null, null, "r"), policy("p2", null, null, "r"),
                        policy("p3", null, null, "r"), policy("p4", null, null, "r"), policy("p5", null, null, "r"),
                        policy("p6", null, null, "r")))
                .put(container).then().statusCode(400);
        containerAcl(given()).get("/" + account + "/missing").then().statusCode(404)
                .header("x-ms-error-code", "ContainerNotFound");
    }

    @Test
    void aBlobSasNamingAPolicyTakesItsPermissionsAndTimesAndIsRevokedWithIt() throws Exception {
        String account = "sapblobsas";
        String key = createAccount(account);
        String container = "/" + account + "/shared";
        given().queryParam("restype", "container").put(container).then().statusCode(201);
        given().header("x-ms-blob-type", "BlockBlob").body("payload").put(container + "/file.txt")
                .then().statusCode(201);
        setContainerPolicies(container, policy("reader", past(), future(), "r"));

        Map<String, String> sas = blobSas(account, "shared", "file.txt", "b", null, null, "reader", key);
        given().queryParams(sas).get(container + "/file.txt").then().statusCode(200).body(containsString("payload"));
        refused(blob(sas).body("new").put(container + "/file.txt"), "AuthorizationPermissionMismatch");

        // Changing the policy changes every SAS that names it, at once.
        setContainerPolicies(container, policy("reader", past(), future(), "rw"));
        blob(sas).body("new").put(container + "/file.txt").then().statusCode(201);

        setContainerPolicies(container, policy("other", past(), future(), "rw"));
        refused(given().queryParams(sas).get(container + "/file.txt"), "AuthenticationFailed")
                .then().body(containsString("<AuthenticationErrorDetail>" + NOT_FOUND + "</AuthenticationErrorDetail>"));

        // A policy created again under the same name brings its SAS back.
        setContainerPolicies(container, policy("reader", past(), future(), "r"));
        given().queryParams(sas).get(container + "/file.txt").then().statusCode(200);

        setContainerPolicies(container, policy("reader", past(), Instant.now().minusSeconds(60).toString(), "r"));
        refused(given().queryParams(sas).get(container + "/file.txt"), "AuthenticationFailed");
    }

    @Test
    void theSasAndThePolicyMayEachHoldSomeFieldsButNotTheSameOne() throws Exception {
        String account = "sapblobfields";
        String key = createAccount(account);
        String container = "/" + account + "/split";
        given().queryParam("restype", "container").put(container).then().statusCode(201);
        given().header("x-ms-blob-type", "BlockBlob").body("payload").put(container + "/file.txt")
                .then().statusCode(201);

        setContainerPolicies(container, policy("expiry-only", null, future(), null));
        given().queryParams(blobSas(account, "split", "file.txt", "b", "r", null, "expiry-only", key))
                .get(container + "/file.txt").then().statusCode(200);
        given().queryParams(blobSas(account, "split", null, "c", "l", null, "expiry-only", key))
                .queryParam("restype", "container").queryParam("comp", "list")
                .get(container).then().statusCode(200).body(containsString("file.txt"));
        bothFields(given().queryParams(blobSas(account, "split", "file.txt", "b", "r", future(), "expiry-only", key))
                .get(container + "/file.txt"))
                .then().body(containsString("Access policy fields can be associated with signature or SAS identifier"
                        + " but not both"));

        setContainerPolicies(container, policy("permission-only", null, null, "r"));
        refused(given().queryParams(blobSas(account, "split", "file.txt", "b", null, null, "permission-only", key))
                .get(container + "/file.txt"), "AuthenticationFailed")
                .then().body(containsString("Signed expiry must be specified in signature or SAS identifier"));
        bothFields(given().queryParams(blobSas(account, "split", "file.txt", "b", "r", future(), "permission-only",
                key)).get(container + "/file.txt"));
        given().queryParams(blobSas(account, "split", "file.txt", "b", null, future(), "permission-only", key))
                .get(container + "/file.txt").then().statusCode(200);

        setContainerPolicies(container, policy("times-only", past(), future(), null));
        refused(given().queryParams(blobSas(account, "split", "file.txt", "b", null, null, "times-only", key))
                .get(container + "/file.txt"), "AuthenticationFailed")
                .then().body(containsString("Signed permission must be specified in signature or SAS identifier"));
    }

    @Test
    void noSasReadsOrSetsAContainerAcl() throws Exception {
        String account = "sapaclsas";
        String key = createAccount(account);
        String container = "/" + account + "/guarded";
        given().queryParam("restype", "container").put(container).then().statusCode(201);
        setContainerPolicies(container, policy("all", past(), future(), "racwdl"));

        Map<String, String> sas = blobSas(account, "guarded", null, "c", null, null, "all", key);
        refused(containerAcl(given().queryParams(sas)).get(container), "AuthorizationFailure");
        refused(containerAcl(given().queryParams(sas)).put(container), "AuthorizationFailure");
    }

    @Test
    void aQueueSasNamingAPolicyTakesItsPermissionsAndIsRevokedWithIt() throws Exception {
        String account = "sapqueuesas";
        String key = createAccount(account);
        String queue = "/" + account + "-queue/orders";
        given().put(queue).then().statusCode(201);
        acl(given()).body(identifiers(policy("consumer", past(), future(), "rp"))).put(queue).then().statusCode(204);
        String body = "<QueueMessage><MessageText>hello</MessageText></QueueMessage>";
        given().body(body).post(queue + "/messages").then().statusCode(201);

        Map<String, String> sas = queueSas(account, "orders", null, null, "consumer", key);
        given().queryParams(sas).queryParam("peekonly", "true").get(queue + "/messages")
                .then().statusCode(200).body(containsString("hello"));
        refused(given().queryParams(sas).body(body).post(queue + "/messages"), "AuthorizationPermissionMismatch");
        bothFields(given().queryParams(queueSas(account, "orders", "r", null, "consumer", key))
                .queryParam("peekonly", "true").get(queue + "/messages"))
                .then().body(containsString("but not both"));

        acl(given()).put(queue).then().statusCode(204);
        refused(given().queryParams(sas).queryParam("peekonly", "true").get(queue + "/messages"),
                "AuthenticationFailed")
                .then().body(containsString("<AuthenticationErrorDetail>" + NOT_FOUND + "</AuthenticationErrorDetail>"));
    }

    @Test
    void aTableSasNamingAPolicyTakesItsPermissionsAndIsRevokedWithIt() throws Exception {
        String account = "saptablesas";
        String key = createAccount(account);
        String base = "/" + account + "-table";
        given().contentType("application/json").body("{\"TableName\":\"Orders\"}").post(base + "/Tables")
                .then().statusCode(201);
        given().contentType("application/json").header("Accept", "application/json;odata=nometadata")
                .body("{\"PartitionKey\":\"p1\",\"RowKey\":\"r1\",\"Total\":3}").post(base + "/Orders")
                .then().statusCode(201);
        acl(given()).body(identifiers(policy("auditor", past(), future(), "r"))).put(base + "/Orders")
                .then().statusCode(204);

        Map<String, String> sas = tableSas(account, "Orders", null, null, "auditor", key);
        table(sas).get(base + "/Orders()").then().statusCode(200).body(containsString("Total"));
        refused(table(sas).body("{\"PartitionKey\":\"p1\",\"RowKey\":\"r2\"}").post(base + "/Orders"),
                "AuthorizationPermissionMismatch");

        // The Table service's OData error has no AuthenticationErrorDetail: each step is told apart by the one after.
        acl(given()).put(base + "/Orders").then().statusCode(204);
        refused(table(sas).get(base + "/Orders()"), "AuthenticationFailed");
        acl(given()).body(identifiers(policy("auditor", past(), Instant.now().minusSeconds(60).toString(), "r")))
                .put(base + "/Orders").then().statusCode(204);
        refused(table(sas).get(base + "/Orders()"), "AuthenticationFailed");
        acl(given()).body(identifiers(policy("auditor", past(), future(), "r"))).put(base + "/Orders")
                .then().statusCode(204);
        table(sas).get(base + "/Orders()").then().statusCode(200);
    }

    private static RequestSpecification containerAcl(RequestSpecification request) {
        return acl(request.queryParam("restype", "container"));
    }

    private static RequestSpecification acl(RequestSpecification request) {
        return request.queryParam("comp", "acl");
    }

    private static RequestSpecification blob(Map<String, String> sas) {
        return given().queryParams(sas).header("x-ms-blob-type", "BlockBlob");
    }

    private static RequestSpecification table(Map<String, String> sas) {
        return given().queryParams(sas).contentType("application/json")
                .header("Accept", "application/json;odata=nometadata");
    }

    private static void setContainerPolicies(String container, String... policies) {
        containerAcl(given()).body(identifiers(policies)).put(container).then().statusCode(200);
    }

    private static String identifiers(String... policies) {
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?><SignedIdentifiers>" + String.join("", policies)
                + "</SignedIdentifiers>";
    }

    /** One {@code SignedIdentifier}; a policy with no field at all has no {@code AccessPolicy}. */
    private static String policy(String id, String start, String expiry, String permission) {
        StringBuilder fields = new StringBuilder();
        if (start != null) {
            fields.append("<Start>").append(start).append("</Start>");
        }
        if (expiry != null) {
            fields.append("<Expiry>").append(expiry).append("</Expiry>");
        }
        if (permission != null) {
            fields.append("<Permission>").append(permission).append("</Permission>");
        }
        return "<SignedIdentifier><Id>" + id + "</Id>"
                + (fields.isEmpty() ? "" : "<AccessPolicy>" + fields + "</AccessPolicy>") + "</SignedIdentifier>";
    }

    private static Response refused(Response response, String code) {
        response.then().statusCode(403).header("x-ms-error-code", code);
        return response;
    }

    /** Set Container, Queue and Table ACL: a field on both the SAS and the policy "fails with status code 400". */
    private static Response bothFields(Response response) {
        response.then().statusCode(400).header("x-ms-error-code", "AuthenticationFailed");
        return response;
    }

    private static String createAccount(String account) {
        given().contentType("application/json").body("{\"location\":\"eastus\"}")
                .when().put(ARM + account + API).then().statusCode(200);
        return given().when().post(ARM + account + "/listKeys" + API).then().statusCode(200)
                .extract().path("keys[1].value");
    }

    private static String past() {
        return Instant.now().minusSeconds(300).toString().replaceAll("\\.\\d+Z$", "Z");
    }

    private static String future() {
        return Instant.now().plusSeconds(3600).toString().replaceAll("\\.\\d+Z$", "Z");
    }

    /**
     * Blob service SAS, 2020-12-06 and later: sp st se /blob/account/container[/blob] si sip spr sv sr snapshot ses
     * rscc rscd rsce rscl rsct.
     */
    private static Map<String, String> blobSas(String account, String container, String blob, String resource,
                                               String permissions, String expiry, String identifier, String key)
            throws Exception {
        String resourceName = "/blob/" + account + "/" + container + (blob == null ? "" : "/" + blob);
        String fields = value(permissions) + "\n\n" + value(expiry) + "\n" + resourceName + "\n" + value(identifier)
                + "\n\n\n" + VERSION + "\n" + resource + "\n\n\n\n\n\n\n";
        Map<String, String> query = sasQuery(permissions, expiry, identifier);
        query.put("sr", resource);
        query.put("sig", hmac(key, fields));
        return query;
    }

    /** Queue service SAS, 2015-04-05 and later: sp st se /queue/account/queue si sip spr sv. */
    private static Map<String, String> queueSas(String account, String queue, String permissions, String expiry,
                                                String identifier, String key) throws Exception {
        String fields = value(permissions) + "\n\n" + value(expiry) + "\n/queue/" + account + "/" + queue + "\n"
                + value(identifier) + "\n\n\n" + VERSION;
        Map<String, String> query = sasQuery(permissions, expiry, identifier);
        query.put("sig", hmac(key, fields));
        return query;
    }

    /** Table service SAS: sp st se /table/account/table si sip spr sv spk srk epk erk, the table lowercase. */
    private static Map<String, String> tableSas(String account, String table, String permissions, String expiry,
                                                String identifier, String key) throws Exception {
        String fields = value(permissions) + "\n\n" + value(expiry) + "\n/table/" + account + "/"
                + table.toLowerCase() + "\n" + value(identifier) + "\n\n\n" + VERSION + "\n\n\n\n";
        Map<String, String> query = sasQuery(permissions, expiry, identifier);
        query.put("tn", table);
        query.put("sig", hmac(key, fields));
        return query;
    }

    private static Map<String, String> sasQuery(String permissions, String expiry, String identifier) {
        Map<String, String> query = new LinkedHashMap<>(Map.of("sv", VERSION, "si", identifier));
        if (permissions != null) {
            query.put("sp", permissions);
        }
        if (expiry != null) {
            query.put("se", expiry);
        }
        return query;
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }

    private static String hmac(String key, String fields) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(fields.getBytes(StandardCharsets.UTF_8)));
    }
}
