package io.floci.az.services.monitor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.az.core.arm.ArmResourceId;
import io.floci.az.core.directory.AzureDirectory;
import io.floci.az.services.managementgroups.ManagementGroupStore;
import io.floci.az.services.monitor.MonitorModels.MonitorResource;
import io.floci.az.services.monitor.activitylog.ActivityLogEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The Activity Log as a subscription diagnostic setting exports it: which entries a setting takes, the exported record
 * (the resource-log schema storage accounts and event hubs receive) and the {@code AzureActivity} row a Log Analytics
 * workspace receives. Entries are exported as they are recorded.
 */
@ApplicationScoped
public class ActivityLogExport {

    static final String TABLE = "AzureActivity";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** Operations begun and not yet ended, whose start the end's {@code durationMs} counts from. */
    private static final int MAX_OPEN_OPERATIONS = 10_000;

    private final ManagementGroupStore managementGroups;
    private final AzureDirectory directory;
    private final Map<String, Instant> begun = new ConcurrentHashMap<>();

    @Inject
    public ActivityLogExport(ManagementGroupStore managementGroups, AzureDirectory directory) {
        this.managementGroups = managementGroups;
        this.directory = directory;
    }

    /**
     * Whether {@code setting} exports {@code event}: an enabled log entry names the event's category, or the
     * {@code allLogs} category group.
     */
    static boolean exports(MonitorResource setting, ActivityLogEvent event) {
        Object logs = setting.properties() == null ? null : setting.properties().get("logs");
        if (!(logs instanceof List<?> entries)) {
            return false;
        }
        for (Object raw : entries) {
            if (raw instanceof Map<?, ?> entry && Boolean.TRUE.equals(entry.get("enabled"))
                    && (event.category().equalsIgnoreCase(String.valueOf(entry.get("category")))
                        || "allLogs".equalsIgnoreCase(String.valueOf(entry.get("categoryGroup"))))) {
                return true;
            }
        }
        return false;
    }

    /** The facts both export forms are built from, computed once per entry. */
    record Exported(ActivityLogEvent event, Map<String, Object> record, String hierarchy) {
    }

    /** Builds the export of {@code event}; call once per recorded entry, since it pairs begin and end entries. */
    Exported export(ActivityLogEvent event) {
        String hierarchy = "Policy".equals(event.category()) ? "" : hierarchy(event);
        return new Exported(event, record(event, durationMs(event), hierarchy), hierarchy);
    }

    /**
     * The exported record: the fields of the resource-log schema in the order Azure writes them, {@code resourceId} and
     * {@code operationName} uppercased, the result as {@code Start} / {@code Success} / {@code Failure} with the
     * sub-status after the status word, the caller's authorization and claims as {@code identity}, and the entry's
     * properties with the export's own {@code eventCategory}, {@code entity}, {@code message} and {@code hierarchy}.
     */
    static Map<String, Object> record(ActivityLogEvent event, long durationMs, String hierarchy) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("time", event.eventTimestamp().toString());
        record.put("resourceId", upper(event.resourceId()));
        record.put("operationName", upper(event.operationName()));
        record.put("category", event.category());
        record.put("resultType", resultType(event.status()));
        record.put("resultSignature", event.status() + "." + (event.subStatus() == null ? "" : event.subStatus()));
        record.put("durationMs", String.valueOf(durationMs));
        if (event.clientIpAddress() != null) {
            record.put("callerIpAddress", event.clientIpAddress());
        }
        record.put("correlationId", event.correlationId());
        Map<String, Object> authorization = new LinkedHashMap<>();
        authorization.put("scope", event.scope());
        authorization.put("action", event.action());
        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("authorization", authorization);
        identity.put("claims", event.claims() == null ? Map.of() : event.claims());
        record.put("identity", identity);
        record.put("level", level(event.level()));
        Map<String, Object> properties = new LinkedHashMap<>();
        if (event.properties() != null) {
            properties.putAll(event.properties());
        }
        properties.put("eventCategory", event.category());
        properties.put("entity", event.resourceId());
        properties.put("message", event.operationName());
        properties.put("hierarchy", hierarchy);
        record.put("properties", properties);
        if (event.tenantId() != null) {
            record.put("tenantId", event.tenantId());
        }
        return record;
    }

    /**
     * The {@code AzureActivity} row of an exported entry in the workspace {@code workspaceId}: the typed columns the
     * table reference lists, with the casing Azure writes them, the deprecated columns ({@code OperationName},
     * {@code Category}, {@code ResourceId} and the like) empty.
     */
    static Map<String, Object> azureActivityRow(Exported exported, String workspaceId) {
        ActivityLogEvent event = exported.event();
        Map<String, Object> record = exported.record();
        @SuppressWarnings("unchecked")
        Map<String, Object> identity = (Map<String, Object>) record.get("identity");
        Map<String, Object> httpRequest = new LinkedHashMap<>();
        if (event.clientIpAddress() != null) {
            httpRequest.put("clientIpAddress", event.clientIpAddress());
        }
        String statusCode = event.properties() == null ? null : event.properties().get("statusCode");
        @SuppressWarnings("unchecked")
        Map<String, Object> properties = new LinkedHashMap<>((Map<String, Object>) record.get("properties"));
        properties.put("caller", event.caller());
        properties.put("eventDataId", event.eventDataId());
        properties.put("eventSubmissionTimestamp", event.submissionTimestamp().toString());
        properties.put("httpRequest", json(httpRequest));
        properties.put("resource", resourceName(event.resourceId()));
        properties.put("resourceGroup", event.resourceGroupName());
        properties.put("resourceProviderValue", upper(event.resourceProviderName()));
        properties.put("subscriptionId", event.subscriptionId());
        properties.put("activityStatusValue", record.get("resultType"));
        properties.put("activitySubstatusValue", statusCode == null ? "" : statusCode);

        Map<String, Object> row = new LinkedHashMap<>();
        row.put("TenantId", workspaceId);
        row.put("SourceSystem", "Azure");
        row.put("CallerIpAddress", event.clientIpAddress() == null ? "" : event.clientIpAddress());
        row.put("CategoryValue", event.category());
        row.put("CorrelationId", event.correlationId());
        row.put("Authorization", json(identity.get("authorization")));
        row.put("Authorization_d", identity.get("authorization"));
        row.put("Claims", json(identity.get("claims")));
        row.put("Claims_d", identity.get("claims"));
        row.put("Level", record.get("level"));
        row.put("OperationNameValue", record.get("operationName"));
        row.put("Properties", json(properties));
        row.put("Properties_d", properties);
        row.put("Caller", event.caller() == null ? "" : event.caller());
        row.put("EventDataId", event.eventDataId());
        row.put("EventSubmissionTimestamp", event.submissionTimestamp().toString());
        row.put("HTTPRequest", json(httpRequest));
        row.put("OperationId", "");
        row.put("ResourceGroup", event.resourceGroupName() == null ? "" : upper(event.resourceGroupName()));
        row.put("ResourceProviderValue", upper(event.resourceProviderName()));
        row.put("ActivityStatusValue", record.get("resultType"));
        row.put("ActivitySubstatusValue", statusCode == null ? "" : statusCode);
        row.put("Hierarchy", exported.hierarchy());
        row.put("TimeGenerated", event.submissionTimestamp().toString());
        row.put("SubscriptionId", lower(event.subscriptionId()));
        row.put("OperationName", "");
        row.put("ActivityStatus", "");
        row.put("ActivitySubstatus", "");
        row.put("Category", "");
        row.put("ResourceId", "");
        row.put("ResourceProvider", "");
        row.put("Resource", "");
        row.put("Type", TABLE);
        row.put("_ResourceId", lower(event.resourceId()));
        row.put("_SubscriptionId", lower(event.subscriptionId()));
        return row;
    }

    /** {@code Start}, {@code Success} or {@code Failure}, as the export writes the entry's status. */
    static String resultType(String status) {
        return switch (status == null ? "" : status) {
            case "Started" -> "Start";
            case "Succeeded" -> "Success";
            case "Failed" -> "Failure";
            default -> status;
        };
    }

    /** The export writes {@code Information} where the REST entry writes {@code Informational}. */
    static String level(String level) {
        return "Informational".equals(level) ? "Information" : level;
    }

    /**
     * {@code {tenant}/{management groups, from the root down}/{subscription}}: where the entry's subscription sits in
     * the tenant's hierarchy, the tenant root group being named after the tenant.
     */
    private String hierarchy(ActivityLogEvent event) {
        String subscriptionId = event.subscriptionId();
        if (subscriptionId == null) {
            return "";
        }
        String tenantId = event.tenantId() != null ? event.tenantId() : directory.tenantOfSubscription(subscriptionId);
        ManagementGroupStore.Group parent = managementGroups.parentOf(tenantId, subscriptionId);
        List<String> chain = new ArrayList<>();
        chain.add(parent.name());
        for (ManagementGroupStore.Group ancestor : managementGroups.ancestors(tenantId, parent.name())) {
            chain.add(ancestor.name());
        }
        Collections.reverse(chain);
        chain.add(subscriptionId);
        return String.join("/", chain);
    }

    /** {@code 0} for a begin entry; for an end entry, the time since its begin entry. */
    private long durationMs(ActivityLogEvent event) {
        String operation = event.operationId();
        if ("BeginRequest".equals(event.eventName())) {
            if (begun.size() >= MAX_OPEN_OPERATIONS) {
                begun.clear();
            }
            begun.put(operation, event.eventTimestamp());
            return 0;
        }
        Instant start = operation == null ? null : begun.remove(operation);
        return start == null ? 0 : Math.max(0, Duration.between(start, event.eventTimestamp()).toMillis());
    }

    /** The name segments of a resource id after its last provider namespace, joined with {@code /}. */
    static String resourceName(String resourceId) {
        return ArmResourceId.parse(resourceId)
            .map(id -> {
                List<String> segments = List.of(id.id().split("/"));
                int provider = -1;
                for (int i = 0; i < segments.size(); i++) {
                    if ("providers".equalsIgnoreCase(segments.get(i))) {
                        provider = i;
                    }
                }
                if (provider < 0 || provider + 2 >= segments.size()) {
                    return "";
                }
                List<String> names = new ArrayList<>();
                for (int i = provider + 3; i < segments.size(); i += 2) {
                    names.add(segments.get(i));
                }
                return String.join("/", names);
            })
            .orElse("");
    }

    private static String upper(String value) {
        return value == null ? "" : value.toUpperCase(Locale.ROOT);
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private static String json(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
