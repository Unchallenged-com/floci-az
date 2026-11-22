package io.floci.az.services.monitor;

import io.floci.az.services.monitor.activitylog.ActivityLogEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@DisplayName("Monitor: the exported Activity Log record, in the resource-log schema")
class ActivityLogExportRecordTest {

    private static final String RESOURCE = "/subscriptions/11b74992-d520-46e1-a9e9-b55c57d2e890/resourceGroups/rg1"
        + "/providers/Microsoft.Authorization/roleAssignments/ee749482-0000-0000-0000-000000000001";

    private static ActivityLogEvent event(String eventName, String status, String subStatus, String level,
                                          Map<String, String> properties) {
        return new ActivityLogEvent("data-1", "op-1", "corr-1", Instant.parse("2025-06-11T20:15:57.245Z"),
            Instant.parse("2025-06-11T20:15:58Z"), "Administrative", eventName, "Microsoft.Authorization/roleAssignments/write",
            level, status, subStatus, "user@contoso.com", Map.of("oid", "o1"), "Microsoft.Authorization/roleAssignments/write",
            RESOURCE, "PUT", "/x", "client-1", "203.0.113.10", RESOURCE, "Microsoft.Authorization/roleAssignments",
            "Microsoft.Authorization", "rg1", "11b74992-d520-46e1-a9e9-b55c57d2e890", "tenant-1", properties);
    }

    @Test
    @SuppressWarnings("unchecked")
    void anEndEntryIsExportedWithTheFieldsAzureWrites() {
        Map<String, Object> record = ActivityLogExport.record(
            event("EndRequest", "Succeeded", "Created", "Informational", Map.of("statusCode", "Created")), 6334, "tenant-1/sub");

        assertEquals(List.of("time", "resourceId", "operationName", "category", "resultType", "resultSignature",
            "durationMs", "callerIpAddress", "correlationId", "identity", "level", "properties", "tenantId"),
            List.copyOf(record.keySet()));
        assertEquals(RESOURCE.toUpperCase(), record.get("resourceId"));
        assertEquals("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", record.get("operationName"));
        assertEquals("Success", record.get("resultType"));
        assertEquals("Succeeded.Created", record.get("resultSignature"));
        assertEquals("6334", record.get("durationMs"));
        assertEquals("Information", record.get("level"));
        Map<String, Object> identity = (Map<String, Object>) record.get("identity");
        assertEquals(Map.of("scope", RESOURCE, "action", "Microsoft.Authorization/roleAssignments/write"),
            identity.get("authorization"));
        Map<String, Object> properties = (Map<String, Object>) record.get("properties");
        assertEquals("Created", properties.get("statusCode"));
        assertEquals("Administrative", properties.get("eventCategory"));
        assertEquals(RESOURCE, properties.get("entity"));
        assertEquals("Microsoft.Authorization/roleAssignments/write", properties.get("message"));
        assertEquals("tenant-1/sub", properties.get("hierarchy"));
    }

    @Test
    void aBeginEntryIsAStartWithAnEmptySubStatus() {
        Map<String, Object> record = ActivityLogExport.record(event("BeginRequest", "Started", "", "Informational", Map.of()),
            0, "h");
        assertEquals("Start", record.get("resultType"));
        assertEquals("Started.", record.get("resultSignature"));
        assertEquals("0", record.get("durationMs"));
        assertFalse(record.containsKey("location"), "the export carries no location");
    }

    @Test
    void theResourceIsTheNamesAfterTheLastProvider() {
        assertEquals("logic-huginn-lab/manual", ActivityLogExport.resourceName(
            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Logic/workflows/logic-huginn-lab/triggers/manual"));
        assertEquals("ee749482-0000-0000-0000-000000000001", ActivityLogExport.resourceName(RESOURCE));
    }
}
