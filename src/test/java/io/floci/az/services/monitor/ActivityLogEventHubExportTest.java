package io.floci.az.services.monitor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("Monitor: the Event Hubs destination of the Activity Log export, its hub and its event body")
class ActivityLogEventHubExportTest {

    @Test
    void theNamespaceIsTheOneTheAuthorizationRuleNames() {
        assertEquals(Optional.of("emulatorNs1"), ActivityLogEventHubExport.namespace(
            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/emulatorNs1"
                + "/authorizationRules/RootManageSharedAccessKey"));
        assertEquals(Optional.empty(), ActivityLogEventHubExport.namespace("/subscriptions/s/resourceGroups/rg"));
    }

    @Test
    void theHubIsTheSettingsOrAzureMonitorsDefault() {
        assertEquals("insights-logs-operational-logs", ActivityLogEventHubExport.hub(null));
        assertEquals("insights-logs-operational-logs", ActivityLogEventHubExport.hub(""));
        assertEquals("activity", ActivityLogEventHubExport.hub("activity"));
    }

    @Test
    void theBodyCarriesTheRecordsUnderRecords() throws Exception {
        JsonNode body = new ObjectMapper().readTree(ActivityLogEventHubExport.body(
            List.of(Map.of("operationName", "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"))));
        assertEquals(1, body.size());
        assertEquals("MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE", body.path("records").path(0).path("operationName").asText());
    }
}
