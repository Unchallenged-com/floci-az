package io.floci.az.compat;

import com.azure.messaging.eventhubs.EventHubConsumerClient;
import com.azure.messaging.eventhubs.EventHubProperties;
import com.azure.messaging.eventhubs.models.EventPosition;
import com.azure.messaging.eventhubs.models.PartitionEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The Activity Log exported through a subscription diagnostic setting to an event hub, read back with the
 * Event Hubs SDK: each entry arrives as an event whose body is {@code {"records": [...]}}.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayName("Activity Log export to Event Hubs through a subscription diagnostic setting")
class ActivityLogEventHubExportCompatibilityTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String SUB = "/subscriptions/00000000-0000-0000-0000-000000000001";
    private static final String RG = SUB + "/resourceGroups/rg-activity-eventhub";
    private static final String SETTING = SUB + "/providers/Microsoft.Insights/diagnosticSettings/activity-to-eventhub";
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @BeforeAll
    void setup() throws Exception {
        EmulatorConfig.assumeEmulatorRunning();
        EmulatorConfig.ensureEventHubNamespace();
        Assumptions.assumeTrue(!EmulatorConfig.eventHubMocked,
                "Event Hubs is in mocked mode (no Artemis broker): export test skipped");
        assertEquals(2, put(RG + "?api-version=2021-04-01", "{\"location\": \"eastus\"}") / 100);
        String rule = RG + "/providers/Microsoft.EventHub/namespaces/" + EmulatorConfig.EVENTHUB_NAMESPACE
                + "/authorizationRules/RootManageSharedAccessKey";
        assertEquals(200, put(SETTING + "?api-version=2021-05-01-preview", """
                {"properties": {"eventHubAuthorizationRuleId": "%s", "eventHubName": "%s",
                  "logs": [{"category": "Administrative", "enabled": true}]}}"""
                .formatted(rule, EmulatorConfig.EVENTHUB_NAME)));
    }

    @AfterAll
    void cleanup() throws Exception {
        HTTP.send(HttpRequest.newBuilder(URI.create(EmulatorConfig.httpBase() + SETTING
                + "?api-version=2021-05-01-preview")).DELETE().build(), HttpResponse.BodyHandlers.discarding());
    }

    private static int put(String path, String body) throws Exception {
        return put(path, body, null);
    }

    private static int put(String path, String body, String correlationId) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(EmulatorConfig.httpBase() + path))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(body));
        if (correlationId != null) {
            request.header("x-ms-correlation-request-id", correlationId);
        }
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    @Test
    @DisplayName("An ARM write's entries arrive on the hub as records")
    void anArmWritesEntriesArriveAsRecords() throws Exception {
        Instant start = Instant.now().minusSeconds(1);
        String correlationId = "activity-export-" + UUID.randomUUID();
        int status = put(RG + "/providers/Microsoft.Storage/storageAccounts/saeh" + UUID.randomUUID().toString()
                .substring(0, 8) + "?api-version=2023-01-01",
                "{\"location\": \"eastus\", \"kind\": \"StorageV2\", \"sku\": {\"name\": \"Standard_LRS\"}}",
                correlationId);
        assertEquals(2, status / 100);

        List<JsonNode> records = new ArrayList<>();
        Instant deadline = Instant.now().plusSeconds(30);
        try (EventHubConsumerClient consumer = EmulatorConfig.eventHubClientBuilder()
                .consumerGroup("$Default").buildConsumerClient()) {
            EventHubProperties properties = consumer.getEventHubProperties();
            while (records.size() < 2 && Instant.now().isBefore(deadline)) {
                records.clear();
                for (String partition : properties.getPartitionIds()) {
                    for (PartitionEvent event : consumer.receiveFromPartition(partition, 100,
                            EventPosition.fromEnqueuedTime(start), Duration.ofSeconds(2))) {
                        JsonNode body = MAPPER.readTree(event.getData().getBodyAsString());
                        for (JsonNode record : body.path("records")) {
                            if (correlationId.equals(record.path("correlationId").asText())) {
                                records.add(record);
                            }
                        }
                    }
                }
            }
        }
        assertEquals(2, records.size(), "the write's start and success, each as a record");
        assertTrue(records.stream().anyMatch(r -> "Start".equals(r.path("resultType").asText())));
        JsonNode success = records.stream().filter(r -> "Success".equals(r.path("resultType").asText()))
                .findFirst().orElseThrow();
        assertEquals("MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE", success.path("operationName").asText());
        assertEquals("Administrative", success.path("category").asText());
        assertTrue(success.path("identity").has("authorization"));
    }
}
