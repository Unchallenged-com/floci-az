package io.floci.az.services.keyvault;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.az.core.AzureRequest;
import io.floci.az.core.RequestUrls;
import io.floci.az.core.auth.BearerClaims;
import io.floci.az.services.monitor.ResourceLogRecord;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The {@code AuditEvent} resource log of a vault: one record per data-plane request the vault answered, which Azure
 * Monitor delivers through the vault's diagnostic settings. A request without a token, answered with the
 * {@code 401} challenge, is the {@code Authentication} operation, as on Azure.
 *
 * <p>Operation names are the Key Vault logging reference's, each the operation of the REST API page that table pairs
 * it with. The record's fields, their types and the {@code properties} each operation carries follow the reference's
 * field table and exported records captured in 2024: {@code resultType} is {@code Success} whatever the status,
 * {@code resultSignature} the status's reason phrase, {@code durationMs} a string, {@code resultDescription} only on
 * a failure, and {@code properties.id} the URI of the object the request named.
 */
@ApplicationScoped
public class KeyVaultAudit {

    static final String CATEGORY = "AuditEvent";
    static final String TABLE = "AZKVAuditLogs";
    private static final List<String> GROUPS = List.of("audit", "allLogs");
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** The TLS version exported records of HTTPS requests carry. */
    private static final String TLS_VERSION = "TLS1_2";

    private final KeyVaultArmService vaults;
    private final Event<ResourceLogRecord> logs;

    @Inject
    public KeyVaultAudit(KeyVaultArmService vaults, Event<ResourceLogRecord> logs) {
        this.vaults = vaults;
        this.logs = logs;
    }

    /** Records the request {@code req} the vault answered with {@code response}, which took {@code durationMs}. */
    void record(AzureRequest req, Response response, Instant start, long durationMs) {
        Optional<KeyVaultArmService.Vault> vault = vaults.vault(req.accountName());
        if (vault.isEmpty() || response == null) {
            return;
        }
        String path = req.resourcePath() == null ? "" : req.resourcePath();
        String trimmed = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        String method = req.method().toUpperCase(Locale.ROOT);
        int status = response.getStatus();
        boolean challenge = status == 401 && (req.headers() == null
            || req.headers().getHeaderString("Authorization") == null);
        String operation = challenge ? "Authentication" : operationName(method, trimmed);
        if (operation == null) {
            return;
        }
        Map<String, Object> body = body(response);
        String base = (req.secure() ? "https://" : "http://") + RequestUrls.resolveAuthority(req);

        Map<String, Object> record = new LinkedHashMap<>();
        record.put("time", start.toString());
        record.put("category", CATEGORY);
        record.put("operationName", operation);
        record.put("resultType", "Success");
        record.put("correlationId", correlationId(req));
        record.put("callerIpAddress", req.remoteAddress());
        Map<String, Object> identity = new LinkedHashMap<>();
        if (!challenge) {
            identity.put("claim", BearerClaims.of(req).values());
        }
        record.put("identity", identity);
        Map<String, Object> properties = new LinkedHashMap<>();
        String id = objectId(trimmed, body, base);
        if (id != null) {
            properties.put("id", id);
        }
        String userAgent = req.headers() == null ? null : req.headers().getHeaderString("User-Agent");
        properties.put("clientInfo", userAgent == null ? "" : userAgent);
        properties.put("httpStatusCode", status);
        properties.put("requestUri", base + "/" + path + (req.rawQuery() == null ? "" : "?" + req.rawQuery()));
        if (!challenge) {
            properties.put(vault.get().rbacAuthorization() ? "isRbacAuthorized" : "isAccessPolicyMatch", true);
        }
        properties.putAll(objectProperties(operation, status, body));
        if (req.secure()) {
            properties.put("tlsVersion", TLS_VERSION);
        }
        record.put("properties", properties);
        record.put("resourceId", vault.get().id().id().toUpperCase(Locale.ROOT));
        String apiVersion = req.queryParams() == null ? null : req.queryParams().get("api-version");
        record.put("operationVersion", apiVersion == null ? "" : apiVersion);
        record.put("resultSignature", reasonPhrase(status));
        if (status >= 400 && errorMessage(body) != null) {
            record.put("resultDescription", errorMessage(body));
        }
        record.put("durationMs", String.valueOf(durationMs));

        logs.fire(new ResourceLogRecord(vault.get().id().id(), CATEGORY, GROUPS, start, record, TABLE,
            dedicatedRow(record, vault.get().id().id(), start)));
    }

    /**
     * The operation of a data-plane request, as the logging reference names it; null for a request it names none for.
     * {@code path} is the request path without its trailing slash.
     */
    static String operationName(String method, String path) {
        String[] s = path.isEmpty() ? new String[0] : path.split("/");
        String collection = s.length == 0 ? "" : s[0].toLowerCase(Locale.ROOT);
        String last = s.length == 0 ? "" : s[s.length - 1].toLowerCase(Locale.ROOT);
        return switch (collection) {
            case "secrets" -> secrets(method, s, last);
            case "deletedsecrets" -> deleted("Secret", method, s, last);
            case "keys" -> keys(method, s, last);
            case "deletedkeys" -> deleted("Key", method, s, last);
            case "certificates" -> certificates(method, s, last);
            case "deletedcertificates" -> deleted("Certificate", method, s, last);
            default -> null;
        };
    }

    private static String secrets(String method, String[] s, String last) {
        if (s.length == 1) {
            return "GET".equals(method) ? "SecretList" : null;
        }
        if (s.length == 2 && "restore".equals(last) && "POST".equals(method)) {
            return "SecretRestore";
        }
        if (s.length == 3 && "versions".equals(last)) {
            return "GET".equals(method) ? "SecretListVersions" : null;
        }
        if (s.length == 3 && "backup".equals(last)) {
            return "POST".equals(method) ? "SecretBackup" : null;
        }
        return switch (method) {
            case "GET" -> "SecretGet";
            case "PUT" -> s.length == 2 ? "SecretSet" : null;
            case "PATCH" -> "SecretUpdate";
            case "DELETE" -> s.length == 2 ? "SecretDelete" : null;
            default -> null;
        };
    }

    private static String keys(String method, String[] s, String last) {
        if (s.length == 1) {
            return "GET".equals(method) ? "KeyList" : null;
        }
        if (s.length == 2 && "restore".equals(last) && "POST".equals(method)) {
            return "KeyRestore";
        }
        if (s.length >= 3 && "POST".equals(method)) {
            return switch (last) {
                case "create" -> "KeyCreate";
                case "backup" -> "KeyBackup";
                case "rotate" -> "KeyRotate";
                case "sign" -> "KeySign";
                case "verify" -> "KeyVerify";
                case "wrapkey" -> "KeyWrap";
                case "unwrapkey" -> "KeyUnwrap";
                case "encrypt" -> "KeyEncrypt";
                case "decrypt" -> "KeyDecrypt";
                default -> null;
            };
        }
        if (s.length == 3 && "versions".equals(last)) {
            return "GET".equals(method) ? "KeyListVersions" : null;
        }
        if (s.length == 3 && "rotationpolicy".equals(last)) {
            return switch (method) {
                case "GET" -> "KeyRotationPolicyGet";
                case "PUT" -> "KeyRotationPolicySet";
                default -> null;
            };
        }
        return switch (method) {
            case "GET" -> "KeyGet";
            case "PUT" -> s.length == 2 ? "KeyImport" : null;
            case "PATCH" -> "KeyUpdate";
            case "DELETE" -> s.length == 2 ? "KeyDelete" : null;
            default -> null;
        };
    }

    private static String certificates(String method, String[] s, String last) {
        if (s.length == 1) {
            return "GET".equals(method) ? "CertificateList" : null;
        }
        String second = s[1].toLowerCase(Locale.ROOT);
        if ("contacts".equals(second) && s.length == 2) {
            return switch (method) {
                case "GET" -> "CertificateContactsGet";
                case "PUT" -> "CertificateContactsSet";
                case "DELETE" -> "CertificateContactsDelete";
                default -> null;
            };
        }
        if ("issuers".equals(second)) {
            if (s.length == 2) {
                return "GET".equals(method) ? "CertificateIssuersList" : null;
            }
            return switch (method) {
                case "GET" -> "CertificateIssuerGet";
                case "PUT" -> "CertificateIssuerSet";
                case "PATCH" -> "CertificateIssuerUpdate";
                case "DELETE" -> "CertificateIssuerDelete";
                default -> null;
            };
        }
        if (s.length == 2 && "restore".equals(last) && "POST".equals(method)) {
            return "CertificateRestore";
        }
        if (s.length == 3) {
            switch (last) {
                case "create" -> {
                    return "POST".equals(method) ? "CertificateCreate" : null;
                }
                case "import" -> {
                    return "POST".equals(method) ? "CertificateImport" : null;
                }
                case "backup" -> {
                    return "POST".equals(method) ? "CertificateBackup" : null;
                }
                case "versions" -> {
                    return "GET".equals(method) ? "CertificateListVersions" : null;
                }
                case "policy" -> {
                    return switch (method) {
                        case "GET" -> "CertificatePolicyGet";
                        case "PATCH" -> "CertificatePolicyUpdate";
                        default -> null;
                    };
                }
                case "pending" -> {
                    return switch (method) {
                        case "GET" -> "CertificatePendingGet";
                        case "PATCH" -> "CertificatePendingUpdate";
                        case "DELETE" -> "CertificatePendingDelete";
                        default -> null;
                    };
                }
                default -> {
                    // a version segment
                }
            }
        }
        if (s.length == 4 && "pending".equals(s[2].toLowerCase(Locale.ROOT)) && "merge".equals(last)) {
            return "POST".equals(method) ? "CertificatePendingMerge" : null;
        }
        return switch (method) {
            case "GET" -> "CertificateGet";
            case "PATCH" -> "CertificateUpdate";
            case "DELETE" -> s.length == 2 ? "CertificateDelete" : null;
            default -> null;
        };
    }

    private static String deleted(String kind, String method, String[] s, String last) {
        if (s.length == 1) {
            return "GET".equals(method) ? kind + "ListDeleted" : null;
        }
        if (s.length == 3 && "recover".equals(last)) {
            return "POST".equals(method) ? kind + "Recover" : null;
        }
        return switch (method) {
            case "GET" -> kind + "GetDeleted";
            case "DELETE" -> kind + "Purge";
            default -> null;
        };
    }

    /**
     * {@code properties.id}: the URI of the object the request names, its collection, name and version, without an
     * action segment; for a restore, the object the response returns; none for a listing.
     */
    static String objectId(String path, Map<String, Object> body, String base) {
        String[] s = path.isEmpty() ? new String[0] : path.split("/");
        if (s.length < 2 || "contacts".equalsIgnoreCase(s[1]) || "issuers".equalsIgnoreCase(s[1])) {
            return null;
        }
        if ("restore".equalsIgnoreCase(s[1])) {
            Object id = body.get("id") != null ? body.get("id")
                : body.get("key") instanceof Map<?, ?> key ? key.get("kid") : null;
            if (!(id instanceof String text)) {
                return null;
            }
            String[] parts = text.split("/");
            return parts.length >= 5 ? base + "/" + parts[3] + "/" + parts[4] : text;
        }
        StringBuilder id = new StringBuilder(base).append('/').append(s[0]).append('/').append(s[1]);
        if (s.length >= 3 && !isAction(s[2])) {
            id.append('/').append(s[2]);
        }
        return id.toString();
    }

    private static boolean isAction(String segment) {
        return switch (segment.toLowerCase(Locale.ROOT)) {
            case "versions", "backup", "create", "import", "rotate", "sign", "verify", "wrapkey", "unwrapkey",
                 "encrypt", "decrypt", "rotationpolicy", "policy", "pending", "recover" -> true;
            default -> false;
        };
    }

    /**
     * The object details exported records carry for an operation that succeeded: the key's type and attributes for a
     * key read, update or delete, the secret's attributes for a secret update.
     */
    static Map<String, Object> objectProperties(String operation, int status, Map<String, Object> body) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (status / 100 != 2) {
            return out;
        }
        Map<?, ?> attributes = body.get("attributes") instanceof Map<?, ?> a ? a : Map.of();
        switch (operation) {
            case "KeyGet", "KeyDelete", "KeyUpdate" -> {
                if (body.get("key") instanceof Map<?, ?> key) {
                    Map<String, Object> keyProperties = new LinkedHashMap<>();
                    keyProperties.put("type", key.get("kty"));
                    Map<String, Object> keyAttributes = new LinkedHashMap<>();
                    if ("KeyUpdate".equals(operation)) {
                        keyProperties.put("operations", key.get("key_ops"));
                        putIfPresent(keyAttributes, "enabled", attributes.get("enabled"));
                        putIfPresent(keyAttributes, "exp", attributes.get("exp"));
                    }
                    keyAttributes.put("hsmPlatform", "0");
                    keyProperties.put("attributes", keyAttributes);
                    out.put("keyProperties", keyProperties);
                }
            }
            case "SecretUpdate" -> {
                Map<String, Object> secretAttributes = new LinkedHashMap<>();
                putIfPresent(secretAttributes, "enabled", attributes.get("enabled"));
                putIfPresent(secretAttributes, "exp", attributes.get("exp"));
                out.put("secretProperties", Map.of("attributes", secretAttributes));
            }
            default -> {
                // the 2024 records show no object details for the other operations
            }
        }
        return out;
    }

    private static void putIfPresent(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    /**
     * The row of the resource-specific {@code AZKVAuditLogs} table, with the columns the table reference lists for the
     * record's fields.
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> dedicatedRow(Map<String, Object> record, String resourceId, Instant time) {
        Map<String, Object> properties = (Map<String, Object>) record.get("properties");
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("TimeGenerated", time.toString());
        row.put("OperationName", record.get("operationName"));
        row.put("OperationVersion", record.get("operationVersion"));
        row.put("ResultType", record.get("resultType"));
        row.put("ResultSignature", record.get("resultSignature"));
        row.put("ResultDescription", record.getOrDefault("resultDescription", ""));
        row.put("DurationMs", Integer.parseInt(String.valueOf(record.get("durationMs"))));
        row.put("CallerIpAddress", record.get("callerIpAddress"));
        row.put("CorrelationId", record.get("correlationId"));
        row.put("Identity", record.get("identity"));
        row.put("Properties", properties);
        row.put("Id", properties.getOrDefault("id", ""));
        row.put("ClientInfo", properties.get("clientInfo"));
        row.put("HttpStatusCode", properties.get("httpStatusCode"));
        row.put("RequestUri", properties.get("requestUri"));
        row.put("IsAccessPolicyMatch", properties.getOrDefault("isAccessPolicyMatch", false));
        row.put("IsRbacAuthorized", properties.getOrDefault("isRbacAuthorized", false));
        row.put("Tlsversion", properties.getOrDefault("tlsVersion", ""));
        for (String key : List.of("KeyProperties", "SecretProperties")) {
            String field = Character.toLowerCase(key.charAt(0)) + key.substring(1);
            if (properties.get(field) != null) {
                row.put(key, properties.get(field));
            }
        }
        row.put("SourceSystem", "Azure");
        row.put("Type", TABLE);
        row.put("_ResourceId", resourceId.toLowerCase(Locale.ROOT));
        String[] segments = resourceId.split("/");
        row.put("_SubscriptionId", segments.length > 2 ? segments[2].toLowerCase(Locale.ROOT) : "");
        return row;
    }

    private static String correlationId(AzureRequest req) {
        String sent = req.headers() == null ? null : req.headers().getHeaderString("x-ms-client-request-id");
        return sent == null || sent.isBlank() ? UUID.randomUUID().toString() : sent.trim();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> body(Response response) {
        Object entity = response.getEntity();
        try {
            if (entity instanceof Map<?, ?> map) {
                return (Map<String, Object>) map;
            }
            if (entity instanceof String text && text.startsWith("{")) {
                return MAPPER.readValue(text, Map.class);
            }
            if (entity instanceof byte[] bytes && bytes.length > 0 && bytes[0] == '{') {
                return MAPPER.readValue(bytes, Map.class);
            }
        } catch (Exception e) {
            // a body that is not a JSON object carries no details for the record
        }
        return Map.of();
    }

    private static String errorMessage(Map<String, Object> body) {
        return body.get("error") instanceof Map<?, ?> error && error.get("message") instanceof String message
            ? message : null;
    }

    /** The reason phrase of an HTTP status, which the record's {@code resultSignature} carries. */
    static String reasonPhrase(int status) {
        Response.Status known = Response.Status.fromStatusCode(status);
        return known == null ? String.valueOf(status) : known.getReasonPhrase();
    }
}
