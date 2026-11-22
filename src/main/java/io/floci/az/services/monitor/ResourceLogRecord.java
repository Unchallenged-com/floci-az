package io.floci.az.services.monitor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.az.core.arm.ArmResourceId;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * One resource log record a service emits, which Azure Monitor delivers through the diagnostic settings of the
 * resource that take its category: to a storage account, an event hub and a Log Analytics workspace.
 *
 * @param resourceId     the ARM id of the resource the record is about
 * @param category       the log category, such as {@code AuditEvent}
 * @param categoryGroups the category groups the category belongs to ({@code audit}, {@code allLogs})
 * @param time           when the operation happened
 * @param record         the record in the resource-log schema, as storage accounts and event hubs receive it
 * @param dedicatedTable the resource-specific Log Analytics table, for a setting whose
 *                       {@code logAnalyticsDestinationType} is {@code Dedicated}; null when the category has none
 * @param dedicatedRow   the record's row in {@code dedicatedTable}, keyed by column
 */
public record ResourceLogRecord(String resourceId, String category, List<String> categoryGroups, Instant time,
                                Map<String, Object> record, String dedicatedTable, Map<String, Object> dedicatedRow) {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final DateTimeFormatter HOUR =
        DateTimeFormatter.ofPattern("'y='yyyy'/m='MM'/d='dd'/h='HH'/m=00'").withZone(ZoneOffset.UTC);
    private static final Pattern GUID =
        Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    /** The columns of the resource-log schema that AzureDiagnostics keeps under their own names. */
    private static final Map<String, String> COMMON_COLUMNS = Map.ofEntries(
        Map.entry("operationName", "OperationName"), Map.entry("operationVersion", "OperationVersion"),
        Map.entry("resultType", "ResultType"), Map.entry("resultSignature", "ResultSignature"),
        Map.entry("resultDescription", "ResultDescription"), Map.entry("callerIpAddress", "CallerIPAddress"),
        Map.entry("correlationId", "CorrelationId"));

    /** {@code insights-logs-{category}}: the storage container, and the event hub when the setting names none. */
    public String destinationName() {
        return "insights-logs-" + category.toLowerCase(Locale.ROOT);
    }

    /** {@code resourceId=/{RESOURCE ID}/y={yyyy}/m={MM}/d={dd}/h={HH}/m=00/PT1H.json}, uppercased, by the hour in UTC. */
    public String blobName() {
        return "resourceId=" + resourceId.toUpperCase(Locale.ROOT) + "/" + HOUR.format(time) + "/PT1H.json";
    }

    /**
     * The record's row in the shared {@code AzureDiagnostics} table: the resource-log schema's own columns, the
     * resource's id split into {@code ResourceGroup}, {@code ResourceProvider}, {@code ResourceType} and
     * {@code Resource} in uppercase, and every other field flattened into a column named after its path joined by
     * {@code _}, claims under {@code identity_claim_}, with the suffix of its type: {@code _s} for a string,
     * {@code _g} for a GUID, {@code _d} for a number and {@code _b} for a boolean. A list is not flattened: it is
     * one {@code _s} column holding the list as compact JSON ({@code ["sign","verify"]}).
     */
    public Map<String, Object> azureDiagnosticsRow(String workspaceId) {
        Map<String, Object> row = new LinkedHashMap<>();
        ArmResourceId id = ArmResourceId.parse(resourceId).orElse(null);
        row.put("TenantId", workspaceId);
        row.put("TimeGenerated", time.toString());
        row.put("ResourceId", resourceId.toUpperCase(Locale.ROOT));
        row.put("Category", category);
        row.put("ResourceGroup", id == null || id.resourceGroup() == null ? "" : id.resourceGroup().toUpperCase(Locale.ROOT));
        row.put("SubscriptionId", id == null || id.subscriptionId() == null ? "" : id.subscriptionId().toLowerCase(Locale.ROOT));
        row.put("ResourceProvider", id == null || id.providerNamespace() == null ? ""
            : id.providerNamespace().toUpperCase(Locale.ROOT));
        row.put("Resource", id == null || id.name() == null ? "" : id.name().toUpperCase(Locale.ROOT));
        row.put("ResourceType", id == null || id.types().isEmpty() ? "" : id.types().getLast().toUpperCase(Locale.ROOT));
        COMMON_COLUMNS.forEach((field, column) -> {
            if (record.get(field) != null) {
                row.put(column, record.get(field));
            }
        });
        if (record.get("durationMs") != null) {
            row.put("DurationMs", Long.parseLong(String.valueOf(record.get("durationMs"))));
        }
        if (record.get("identity") instanceof Map<?, ?> identity && identity.get("claim") instanceof Map<?, ?> claims) {
            flatten(row, "identity_claim", claims);
        }
        if (record.get("properties") instanceof Map<?, ?> properties) {
            flatten(row, "", properties);
        }
        row.put("SourceSystem", "Azure");
        row.put("Type", "AzureDiagnostics");
        row.put("_ResourceId", resourceId.toLowerCase(Locale.ROOT));
        return row;
    }

    private static void flatten(Map<String, Object> row, String prefix, Map<?, ?> values) {
        values.forEach((key, value) -> {
            String name = (prefix.isEmpty() ? "" : prefix + "_") + String.valueOf(key).replaceAll("[^A-Za-z0-9]", "_");
            if (value instanceof Map<?, ?> nested) {
                flatten(row, name, nested);
            } else if (value instanceof Boolean flag) {
                row.put(name + "_b", flag);
            } else if (value instanceof Number number) {
                row.put(name + "_d", number.doubleValue());
            } else if (value instanceof String text) {
                row.put(name + (GUID.matcher(text).matches() ? "_g" : "_s"), text);
            } else if (value instanceof Collection<?> list) {
                row.put(name + "_s", json(list));
            } else if (value != null) {
                row.put(name + "_s", String.valueOf(value));
            }
        });
    }

    private static String json(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
