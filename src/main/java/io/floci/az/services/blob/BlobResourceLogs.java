package io.floci.az.services.blob;

import io.floci.az.core.AuthType;
import io.floci.az.core.AzureRequest;
import io.floci.az.core.RequestUrls;
import io.floci.az.core.auth.BearerClaims;
import io.floci.az.core.auth.StorageAccountKeys;
import io.floci.az.core.auth.StorageSasAuthorization;
import io.floci.az.core.auth.StorageSasToken;
import io.floci.az.core.cloud.CloudCatalog;
import io.floci.az.core.cloud.CloudProfile;
import io.floci.az.services.monitor.ResourceLogRecord;
import io.floci.az.services.storageaccounts.StorageAccountArmService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The Blob service's resource logs: one {@code StorageRead}, {@code StorageWrite} or {@code StorageDelete} record per
 * request the service answers for an account the management plane holds, which Azure Monitor delivers through the
 * diagnostic settings of the account's {@code blobServices/default}. Blob logs have no {@code AzureDiagnostics} form:
 * a workspace receives them in {@code StorageBlobLogs}.
 *
 * <p>Categories: the pairs that genuine records and Log Analytics rows show (GetBlob, GetBlobProperties, ListBlobs,
 * ListContainers, GetContainerProperties, GetBlobTags and GetBlobServiceProperties in {@code StorageRead}; PutBlob,
 * PutPage and CreateContainer in {@code StorageWrite}; DeleteContainer in {@code StorageDelete}); the other operations
 * follow the same split by what they do.
 *
 * <p>Fields follow the Blob storage monitoring reference and exported records captured in 2024 and 2025:
 * {@code statusCode} and {@code durationMs} are numbers, {@code statusText} is {@code Success} or the error code,
 * {@code correlationId} the request id the service answers with, {@code callerIpAddress} carries the port, the
 * resource id and the blob path keep their case. As the reference says, activity in the {@code insights-logs-}
 * containers is not logged; failed anonymous requests are, as the exported records show them, although the reference
 * says only some are.
 */
@ApplicationScoped
public class BlobResourceLogs {

    static final String TABLE = "StorageBlobLogs";
    private static final List<String> GROUPS = List.of("audit", "allLogs");
    private static final Pattern ERROR_CODE = Pattern.compile("<Code>([^<]+)</Code>");
    private static final String TLS_VERSION = "TLS 1.2";

    private final StorageAccountArmService accounts;
    private final Event<ResourceLogRecord> logs;
    private final StorageAccountKeys keys;
    private final StorageSasAuthorization sasAuthorization;

    @Inject
    public BlobResourceLogs(StorageAccountArmService accounts, Event<ResourceLogRecord> logs, StorageAccountKeys keys,
                            StorageSasAuthorization sasAuthorization) {
        this.accounts = accounts;
        this.logs = logs;
        this.keys = keys;
        this.sasAuthorization = sasAuthorization;
    }

    void record(AzureRequest req, Response response, Instant start, long durationMs) {
        if (response == null || req.accountName() == null) {
            return;
        }
        Optional<StorageAccountArmService.Account> account = accounts.account(req.accountName());
        if (account.isEmpty()) {
            return;
        }
        String path = req.resourcePath() == null ? "" : req.resourcePath();
        while (path.startsWith("/")) {
            path = path.substring(1);
        }
        String container = path.isEmpty() ? "" : path.split("/", 2)[0];
        if (container.toLowerCase(Locale.ROOT).startsWith("insights-logs-")) {
            return;
        }
        String operation = operationName(req.method(), path, req.queryParams(), header(req, "x-ms-copy-source"),
            header(req, "x-ms-lease-action"), header(req, "x-ms-page-write"));
        if (operation == null) {
            return;
        }
        int status = response.getStatus();
        String type = authenticationType(req);
        String resourceId = account.get().id().id() + "/blobServices/default";
        String category = category(operation);
        String statusText = status / 100 == 2 || status == 304 ? "Success" : errorCode(response);
        String scheme = req.secure() ? "https" : "http";

        Map<String, Object> record = new LinkedHashMap<>();
        record.put("time", start.toString());
        record.put("resourceId", resourceId);
        record.put("category", category);
        record.put("operationName", operation);
        String version = header(req, "x-ms-version");
        if (version != null) {
            record.put("operationVersion", version);
        }
        record.put("schemaVersion", "1.0");
        record.put("statusCode", status);
        record.put("statusText", statusText);
        record.put("durationMs", durationMs);
        if (req.remoteAddress() != null) {
            record.put("callerIpAddress", req.remoteAddress());
        }
        String requestId = response.getHeaderString("x-ms-request-id");
        record.put("correlationId", requestId == null ? UUID.randomUUID().toString() : requestId);
        Map<String, Object> identity = identity(req, type);
        keyHash(req, container, path.contains("/") ? path.split("/", 2)[1] : "")
            .ifPresent(hash -> identity.put("tokenHash", hash));
        record.put("identity", identity);
        if (account.get().location() != null) {
            record.put("location", account.get().location());
        }
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("accountName", req.accountName());
        putIfPresent(properties, "userAgentHeader", header(req, "User-Agent"));
        putIfPresent(properties, "referrerHeader", header(req, "Referer"));
        putIfPresent(properties, "clientRequestId", header(req, "x-ms-client-request-id"));
        putIfPresent(properties, "etag", response.getHeaderString("ETag"));
        properties.put("serviceType", "blob");
        properties.put("objectKey", "/" + req.accountName() + (path.isEmpty() ? "" : "/" + path));
        properties.put("metricResponseType", metricResponseType(status));
        properties.put("serverLatencyMs", durationMs);
        properties.put("requestHeaderSize", headerSize(req.headers() == null ? Map.of() : req.headers().getRequestHeaders()));
        properties.put("responseHeaderSize", headerSize(response.getStringHeaders()));
        String contentLength = header(req, "Content-Length");
        if (contentLength != null && !"0".equals(contentLength)) {
            properties.put("requestBodySize", Long.parseLong(contentLength.trim()));
        }
        long responseBodySize = bodySize(response);
        if (responseBodySize > 0) {
            properties.put("responseBodySize", responseBodySize);
        }
        if (req.secure()) {
            properties.put("tlsVersion", TLS_VERSION);
        }
        record.put("properties", properties);
        record.put("uri", scheme + "://" + RequestUrls.resolveAuthority(req) + "/" + (req.rawPath() == null ? path
            : req.rawPath()) + (req.rawQuery() == null ? "" : "?" + req.rawQuery()));
        record.put("protocol", req.secure() ? "HTTPS" : "HTTP");
        record.put("resourceType", "Microsoft.Storage/storageAccounts/blobServices");

        logs.fire(new ResourceLogRecord(resourceId, category, GROUPS, start, record, TABLE,
            row(record, resourceId, start), resourceId, true));
    }

    /**
     * The operation the logged operations reference names for a request; null for one it names none for. {@code path}
     * is relative to the account: empty for the service, a container, or a container and blob.
     */
    static String operationName(String method, String path, Map<String, String> query, String copySource,
                                String leaseAction, String pageWrite) {
        String m = method == null ? "" : method.toUpperCase(Locale.ROOT);
        String comp = query == null || query.get("comp") == null ? "" : query.get("comp").toLowerCase(Locale.ROOT);
        String restype = query == null || query.get("restype") == null ? "" : query.get("restype").toLowerCase(Locale.ROOT);
        boolean read = "GET".equals(m) || "HEAD".equals(m);
        if ("OPTIONS".equals(m)) {
            return "BlobPreflightRequest";
        }
        if (path.isEmpty()) {
            if ("account".equals(restype) && "properties".equals(comp) && read) {
                return "GetAccountInformation";
            }
            return switch (comp) {
                case "list" -> read ? "ListContainers" : null;
                case "properties" -> read ? "GetBlobServiceProperties" : "PUT".equals(m) ? "SetBlobServiceProperties" : null;
                case "stats" -> read ? "GetBlobServiceStats" : null;
                case "userdelegationkey" -> "POST".equals(m) ? "GetUserDelegationKey" : null;
                case "blobs" -> read ? "FindBlobsByTags" : null;
                default -> null;
            };
        }
        if (!path.contains("/")) {
            if (!"container".equals(restype)) {
                return null;
            }
            return switch (comp) {
                case "" -> switch (m) {
                    case "PUT" -> "CreateContainer";
                    case "GET", "HEAD" -> "GetContainerProperties";
                    case "DELETE" -> "DeleteContainer";
                    default -> null;
                };
                case "metadata" -> read ? "GetContainerMetadata" : "PUT".equals(m) ? "SetContainerMetadata" : null;
                case "acl" -> read ? "GetContainerACL" : "PUT".equals(m) ? "SetContainerACL" : null;
                case "list" -> read ? "ListBlobs" : null;
                case "lease" -> lease("Container", leaseAction);
                default -> null;
            };
        }
        return switch (comp) {
            case "" -> switch (m) {
                case "GET" -> "GetBlob";
                case "HEAD" -> "GetBlobProperties";
                case "PUT" -> copySource != null ? "CopyBlob" : "PutBlob";
                case "DELETE" -> "DeleteBlob";
                default -> null;
            };
            case "metadata" -> read ? "GetBlobMetadata" : "PUT".equals(m) ? "SetBlobMetadata" : null;
            case "properties" -> "PUT".equals(m) ? "SetBlobProperties" : null;
            case "block" -> "PUT".equals(m) ? (copySource != null ? "PutBlockFromURL" : "PutBlock") : null;
            case "blocklist" -> read ? "GetBlockList" : "PUT".equals(m) ? "PutBlockList" : null;
            case "appendblock" -> "PUT".equals(m) ? "AppendBlock" : null;
            case "page" -> "PUT".equals(m) ? ("clear".equalsIgnoreCase(pageWrite) ? "ClearPage" : "PutPage") : null;
            case "pagelist" -> read ? "GetPageRanges" : null;
            case "snapshot" -> "PUT".equals(m) ? "SnapshotBlob" : null;
            case "copy" -> "PUT".equals(m) ? "AbortCopyBlob" : null;
            case "lease" -> lease("Blob", leaseAction);
            case "tags" -> read ? "GetBlobTags" : "PUT".equals(m) ? "SetBlobTags" : null;
            case "tier" -> "PUT".equals(m) ? "SetBlobTier" : null;
            case "undelete" -> "PUT".equals(m) ? "UndeleteBlob" : null;
            case "expiry" -> "PUT".equals(m) ? "SetBlobExpiry" : null;
            case "query" -> "POST".equals(m) ? "QueryBlobContents" : null;
            default -> null;
        };
    }

    private static String lease(String kind, String action) {
        if (action == null) {
            return null;
        }
        return switch (action.toLowerCase(Locale.ROOT)) {
            case "acquire" -> "Acquire" + kind + "Lease";
            case "break" -> "Break" + kind + "Lease";
            case "change" -> "Change" + kind + "Lease";
            case "renew" -> "Renew" + kind + "Lease";
            case "release" -> "Release" + kind + "Lease";
            default -> null;
        };
    }

    /** {@code StorageDelete} for a delete, {@code StorageRead} for a read, {@code StorageWrite} for anything else. */
    static String category(String operation) {
        if (operation.startsWith("Delete")) {
            return "StorageDelete";
        }
        if (operation.startsWith("Get") || operation.startsWith("List") || operation.startsWith("Find")
                || operation.startsWith("Query") || "BlobPreflightRequest".equals(operation)) {
            return "StorageRead";
        }
        return "StorageWrite";
    }

    /** {@code identity.type}: how the request authenticated, as exported records name it. */
    static String authenticationType(AzureRequest req) {
        if (req.authContext() == null) {
            return header(req, "Authorization") != null ? "AccountKey" : "Anonymous";
        }
        AuthType type = req.authContext().type();
        return switch (type) {
            case SHARED_KEY -> "AccountKey";
            case SAS -> req.authContext().storageSas().map(sas -> sas.isUserDelegation() ? "DelegationSAS" : "SAS")
                .orElse("SAS");
            case BEARER -> "OAuth";
            case ANONYMOUS -> "Anonymous";
        };
    }

    private static Map<String, Object> identity(AzureRequest req, String type) {
        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("type", type);
        if ("OAuth".equals(type)) {
            String authorization = header(req, "Authorization");
            if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
                identity.put("tokenHash", sha256(authorization.substring(7).trim()));
            }
            Map<String, Object> claims = BearerClaims.of(req).values();
            Map<String, Object> requester = new LinkedHashMap<>();
            putIfPresent(requester, "appId", claims.get("appid") != null ? claims.get("appid") : claims.get("azp"));
            putIfPresent(requester, "audience", claims.get("aud"));
            putIfPresent(requester, "objectId", claims.get("oid"));
            putIfPresent(requester, "tenantId", claims.get("tid"));
            putIfPresent(requester, "tokenIssuer", claims.get("iss"));
            putIfPresent(requester, "upn", claims.get("upn"));
            identity.put("requester", requester);
        }
        return identity;
    }

    /**
     * {@code identity.tokenHash} of a request an account key signed: "key1 | key2 (SHA256 hash of the key)" for
     * Shared Key, followed by ",SasSignature(SHA 256 hash of the SAS token)" for a SAS. The key is hashed as its
     * base64 text, and the SAS as its {@code sig} value, URL-decoded. Empty when no current key signed the request.
     */
    private Optional<String> keyHash(AzureRequest req, String container, String blob) {
        if (req.authContext() == null) {
            return Optional.empty();
        }
        AuthType type = req.authContext().type();
        Optional<StorageSasToken> sas = req.authContext().storageSas();
        Optional<String> signer = req.authContext().signingKey();
        if (type == AuthType.SAS && signer.isEmpty() && sas.isPresent()) {
            signer = sasAuthorization.signer(req, container, blob, sas.get());
        }
        if (signer.isEmpty() || (type != AuthType.SHARED_KEY && type != AuthType.SAS)) {
            return Optional.empty();
        }
        String keyHash = signer.get() + "(" + sha256(keys.value(req.accountName(), signer.get())) + ")";
        return Optional.of(type == AuthType.SAS && sas.isPresent()
            ? keyHash + ",SasSignature(" + sha256(sas.get().signature()) + ")"
            : keyHash);
    }

    /** The metric response type: {@code Success}, or the class of the failure, as the record's properties carry it. */
    static String metricResponseType(int status) {
        if (status / 100 == 2 || status == 304) {
            return "Success";
        }
        if (status == 401 || status == 403) {
            return "AuthorizationError";
        }
        if (status == 503) {
            return "ServerBusyError";
        }
        return status >= 500 ? "ServerOtherError" : "ClientOtherError";
    }

    private static String errorCode(Response response) {
        String code = response.getHeaderString("x-ms-error-code");
        if (code != null) {
            return code;
        }
        Object entity = response.getEntity();
        String body = entity instanceof String text ? text
            : entity instanceof byte[] bytes ? new String(bytes, StandardCharsets.UTF_8) : null;
        if (body != null) {
            Matcher matcher = ERROR_CODE.matcher(body);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        return "UnknownError";
    }

    /** A location's display name ({@code East US}), as {@code StorageBlobLogs} rows carry it; the name when unknown. */
    static String displayName(String location) {
        for (CloudProfile.Location candidate : CloudCatalog.forNameOrPublic(CloudCatalog.PUBLIC_CLOUD).locations()) {
            if (candidate.name().equalsIgnoreCase(location)) {
                return candidate.displayName();
            }
        }
        return location;
    }

    /** The SHA-256 of {@code value}, in the uppercase hex the records' {@code tokenHash} uses. */
    static String sha256(String value) {
        try {
            return HexFormat.of().withUpperCase().formatHex(
                MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The bytes of a header block: each {@code Name: value} line with its line break. */
    static long headerSize(Map<String, ? extends List<?>> headers) {
        long size = 0;
        for (Map.Entry<String, ? extends List<?>> header : headers.entrySet()) {
            for (Object value : header.getValue()) {
                size += header.getKey().getBytes(StandardCharsets.UTF_8).length + 2
                    + String.valueOf(value).getBytes(StandardCharsets.UTF_8).length + 2;
            }
        }
        return size;
    }

    private static long bodySize(Response response) {
        Object entity = response.getEntity();
        if (entity instanceof byte[] bytes) {
            return bytes.length;
        }
        if (entity instanceof String text) {
            return text.getBytes(StandardCharsets.UTF_8).length;
        }
        String length = response.getHeaderString("Content-Length");
        try {
            return length == null ? 0 : Long.parseLong(length.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** The record's row in {@code StorageBlobLogs}, each column from the record's field of the same name. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> row(Map<String, Object> record, String resourceId, Instant time) {
        Map<String, Object> properties = (Map<String, Object>) record.get("properties");
        Map<String, Object> identity = (Map<String, Object>) record.get("identity");
        Map<String, Object> requester = identity.get("requester") instanceof Map<?, ?> r
            ? (Map<String, Object>) r : Map.of();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("TimeGenerated", time.toString());
        row.put("AccountName", properties.get("accountName"));
        row.put("Location", displayName(String.valueOf(record.getOrDefault("location", ""))));
        row.put("Protocol", record.get("protocol"));
        row.put("OperationName", record.get("operationName"));
        row.put("AuthenticationType", identity.get("type"));
        row.put("StatusCode", String.valueOf(record.get("statusCode")));
        row.put("StatusText", record.get("statusText"));
        row.put("DurationMs", ((Number) record.get("durationMs")).doubleValue());
        row.put("ServerLatencyMs", ((Number) properties.get("serverLatencyMs")).doubleValue());
        row.put("Uri", record.get("uri"));
        row.put("CallerIpAddress", record.getOrDefault("callerIpAddress", ""));
        row.put("CorrelationId", record.get("correlationId"));
        row.put("SchemaVersion", record.get("schemaVersion"));
        row.put("OperationVersion", record.getOrDefault("operationVersion", ""));
        row.put("Category", record.get("category"));
        row.put("UserAgentHeader", properties.getOrDefault("userAgentHeader", ""));
        row.put("ReferrerHeader", properties.getOrDefault("referrerHeader", ""));
        row.put("ClientRequestId", properties.getOrDefault("clientRequestId", ""));
        row.put("Etag", properties.getOrDefault("etag", ""));
        row.put("ServiceType", properties.get("serviceType"));
        row.put("ObjectKey", properties.get("objectKey"));
        row.put("MetricResponseType", properties.get("metricResponseType"));
        row.put("AuthenticationHash", identity.getOrDefault("tokenHash", ""));
        row.put("RequestHeaderSize", properties.getOrDefault("requestHeaderSize", 0L));
        row.put("ResponseHeaderSize", properties.getOrDefault("responseHeaderSize", 0L));
        row.put("RequestBodySize", properties.getOrDefault("requestBodySize", 0L));
        row.put("ResponseBodySize", properties.getOrDefault("responseBodySize", 0L));
        row.put("TlsVersion", properties.getOrDefault("tlsVersion", ""));
        row.put("RequesterAppId", requester.getOrDefault("appId", ""));
        row.put("RequesterAudience", requester.getOrDefault("audience", ""));
        row.put("RequesterObjectId", requester.getOrDefault("objectId", ""));
        row.put("RequesterTenantId", requester.getOrDefault("tenantId", ""));
        row.put("RequesterTokenIssuer", requester.getOrDefault("tokenIssuer", ""));
        row.put("RequesterUpn", requester.getOrDefault("upn", ""));
        row.put("SourceSystem", "Azure");
        row.put("Type", TABLE);
        row.put("_ResourceId", resourceId.toLowerCase(Locale.ROOT));
        String[] segments = resourceId.split("/");
        row.put("_SubscriptionId", segments.length > 2 ? segments[2].toLowerCase(Locale.ROOT) : "");
        return row;
    }

    private static String header(AzureRequest req, String name) {
        return req.headers() == null ? null : req.headers().getHeaderString(name);
    }

    private static void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null && !(value instanceof String text && text.isBlank())) {
            target.put(key, value);
        }
    }
}
