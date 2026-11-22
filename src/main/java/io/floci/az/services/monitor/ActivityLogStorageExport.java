package io.floci.az.services.monitor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.az.core.AzureRequest;
import io.floci.az.core.SyntheticHttpHeaders;
import io.floci.az.core.arm.ArmResourceId;
import io.floci.az.services.blob.BlobServiceHandler;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * The storage account destination of the Activity Log export: each exported record is appended, as one line of JSON,
 * to the hourly append blob {@code resourceId=/SUBSCRIPTIONS/{SUBSCRIPTION}/y={yyyy}/m={MM}/d={dd}/h={HH}/m=00/PT1H.json}
 * of the {@code insights-activity-logs} container of the setting's storage account, both created on first use. The
 * blob is written through the Blob service's own operations, so it reads back like any other.
 */
@ApplicationScoped
public class ActivityLogStorageExport {

    static final String CONTAINER = "insights-activity-logs";
    private static final Logger LOG = Logger.getLogger(ActivityLogStorageExport.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final DateTimeFormatter HOUR =
        DateTimeFormatter.ofPattern("'y='yyyy'/m='MM'/d='dd'/h='HH'/m=00'").withZone(ZoneOffset.UTC);
    private static final String STORAGE_ACCOUNTS = "Microsoft.Storage/storageAccounts";

    private final BlobServiceHandler blobs;

    @Inject
    public ActivityLogStorageExport(BlobServiceHandler blobs) {
        this.blobs = blobs;
    }

    /** The blob an entry of {@code subscriptionId} at {@code time} is appended to. */
    static String blobName(String subscriptionId, Instant time) {
        return "resourceId=/SUBSCRIPTIONS/" + subscriptionId.toUpperCase(Locale.ROOT) + "/" + HOUR.format(time)
            + "/PT1H.json";
    }

    /** The storage account a setting's {@code storageAccountId} names, or empty when it names none. */
    static Optional<String> accountName(String storageAccountId) {
        return ArmResourceId.parse(storageAccountId)
            .filter(id -> STORAGE_ACCOUNTS.equalsIgnoreCase(id.typePath()))
            .map(ArmResourceId::name);
    }

    /** Appends {@code exported}'s record to its hourly blob in the storage account {@code storageAccountId}. */
    void deliver(String storageAccountId, ActivityLogExport.Exported exported) {
        if (exported.event().subscriptionId() == null) {
            return;
        }
        append(storageAccountId, CONTAINER, blobName(exported.event().subscriptionId(), exported.event().eventTimestamp()),
            exported.record());
    }

    /**
     * Appends {@code record}, as one line of JSON, to the append blob {@code blob} of {@code container} in the storage
     * account {@code storageAccountId}, creating both on first use: how Azure Monitor writes the Activity Log and
     * resource logs to a storage account.
     */
    synchronized void append(String storageAccountId, String container, String blob, Map<String, Object> record) {
        Optional<String> account = accountName(storageAccountId);
        if (account.isEmpty()) {
            return;
        }
        byte[] line = (json(record) + "\n").getBytes(StandardCharsets.UTF_8);
        // The container and the blob exist after their first record: the create-only writes answer 409 then.
        send(account.get(), "PUT", container, Map.of("restype", "container"), Map.of(), new byte[0]);
        send(account.get(), "PUT", container + "/" + blob, Map.of(),
            Map.of("x-ms-blob-type", "AppendBlob", "If-None-Match", "*"), new byte[0]);
        Response appended = send(account.get(), "PUT", container + "/" + blob, Map.of("comp", "appendblock"),
            Map.of(), line);
        if (appended.getStatus() / 100 != 2) {
            LOG.warnf("Log export: appending to %s/%s/%s answered %d", account.get(), container, blob,
                appended.getStatus());
        }
    }

    private Response send(String account, String method, String path, Map<String, String> query,
                          Map<String, String> headers, byte[] body) {
        Map<String, String> requestHeaders = new LinkedHashMap<>(headers);
        requestHeaders.put("Content-Length", String.valueOf(body.length));
        InputStream stream = new ByteArrayInputStream(body);
        return blobs.handle(new AzureRequest(method, account, "blob", path, new SyntheticHttpHeaders(requestHeaders),
            stream, query, Map.of(), null, false));
    }

    private static String json(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
