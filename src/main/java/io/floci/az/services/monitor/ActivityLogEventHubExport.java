package io.floci.az.services.monitor;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.az.core.AmqpManagementReply;
import io.floci.az.core.arm.ArmResourceId;
import io.floci.az.services.eventhub.EventHubNamespaceManager;
import io.floci.az.services.eventhub.EventHubNamespaceManager.NamespaceState;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.qpid.proton.Proton;
import org.apache.qpid.proton.amqp.Binary;
import org.apache.qpid.proton.amqp.messaging.Accepted;
import org.apache.qpid.proton.amqp.messaging.Data;
import org.apache.qpid.proton.amqp.messaging.Target;
import org.apache.qpid.proton.engine.BaseHandler;
import org.apache.qpid.proton.engine.Connection;
import org.apache.qpid.proton.engine.Delivery;
import org.apache.qpid.proton.engine.Event;
import org.apache.qpid.proton.engine.Sender;
import org.apache.qpid.proton.engine.Session;
import org.apache.qpid.proton.message.Message;
import org.apache.qpid.proton.reactor.Reactor;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The Event Hubs destination of the Activity Log export: each exported record is sent, as an event whose body is
 * {@code {"records": [...]}}, to the setting's event hub in the namespace its {@code eventHubAuthorizationRuleId}
 * names: {@code eventHubName} when the setting gives one, else {@code insights-logs-operational-logs}, the hub Azure
 * Monitor sends the Activity Log to. The namespace's broker must be running and declare the hub, which Azure would
 * create; nothing is sent otherwise. Events are sent in the background, in the order they were exported, so that an
 * ARM request never waits on the broker.
 */
@ApplicationScoped
public class ActivityLogEventHubExport {

    /** The hub Azure Monitor creates in the namespace for the Activity Log when the setting names none. */
    static final String DEFAULT_HUB = "insights-logs-operational-logs";
    private static final Logger LOG = Logger.getLogger(ActivityLogEventHubExport.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern NAMESPACE = Pattern.compile(
        "(?i)/providers/microsoft\\.eventhub/namespaces/([^/]+)(?:/|$)");
    private static final long SEND_TIMEOUT_SECONDS = 10;

    private final EventHubNamespaceManager namespaces;
    private final ExecutorService sender = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "activity-log-eventhub-export");
        thread.setDaemon(true);
        return thread;
    });

    @Inject
    public ActivityLogEventHubExport(EventHubNamespaceManager namespaces) {
        this.namespaces = namespaces;
    }

    @PreDestroy
    void stop() {
        sender.shutdownNow();
    }

    /** The namespace an authorization rule id names, or empty when it names none. */
    static Optional<String> namespace(String eventHubAuthorizationRuleId) {
        Matcher matcher = NAMESPACE.matcher(eventHubAuthorizationRuleId == null ? "" : eventHubAuthorizationRuleId);
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }

    /** The hub a setting sends to: its {@code eventHubName}, else Azure Monitor's default hub. */
    static String hub(String eventHubName) {
        return eventHubName == null || eventHubName.isBlank() ? DEFAULT_HUB : eventHubName;
    }

    /** The event body Azure Monitor sends: the records under {@code records}. */
    static byte[] body(List<Map<String, Object>> records) {
        try {
            return MAPPER.writeValueAsString(Map.of("records", records)).getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Sends {@code exported}'s record to the hub the setting names, when its namespace's broker runs. */
    void deliver(String eventHubAuthorizationRuleId, String eventHubName, ActivityLogExport.Exported exported) {
        send(eventHubAuthorizationRuleId, hub(eventHubName), exported.record());
    }

    /**
     * Sends {@code record} under {@code records} to the hub {@code hub} of the namespace the authorization rule names,
     * when that namespace's broker runs: how Azure Monitor streams the Activity Log and resource logs.
     */
    void send(String eventHubAuthorizationRuleId, String hub, Map<String, Object> record) {
        Optional<NamespaceState> state = namespace(eventHubAuthorizationRuleId)
            .flatMap(name -> namespaces.listNamespaces().entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(name)).map(Map.Entry::getValue).findFirst());
        if (state.isEmpty() || state.get().mocked() || state.get().amqpHost() == null) {
            LOG.debugv("Activity Log export: no running Event Hubs broker for {0}", eventHubAuthorizationRuleId);
            return;
        }
        String host = state.get().amqpHost();
        int port = state.get().amqpPort();
        byte[] body = body(List.of(record));
        sender.submit(() -> send(host, port, hub, body));
    }

    private static void send(String host, int port, String hub, byte[] body) {
        ExecutorService runner = Executors.newSingleThreadExecutor();
        Reactor[] reactor = new Reactor[1];
        SendHandler handler = new SendHandler(host, port, hub, body);
        try {
            reactor[0] = Proton.reactor(handler);
            Future<?> run = runner.submit(() -> reactor[0].run());
            run.get(SEND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!handler.accepted) {
                LOG.warnf("Activity Log export: the broker at %s:%d did not accept the event for hub %s", host, port, hub);
            }
        } catch (TimeoutException e) {
            LOG.warnf("Activity Log export: sending to hub %s at %s:%d timed out", hub, host, port);
            reactor[0].stop();
        } catch (Exception e) {
            LOG.warnf("Activity Log export: sending to hub %s at %s:%d failed: %s", hub, host, port, e.getMessage());
        } finally {
            runner.shutdownNow();
            if (reactor[0] != null) {
                try {
                    reactor[0].free();
                } catch (RuntimeException e) {
                    LOG.debugv("Activity Log export: failed to free the reactor: {0}", e.getMessage());
                }
            }
        }
    }

    /** Opens a link to the hub, sends the one event once the broker grants credit, and closes on its outcome. */
    private static final class SendHandler extends BaseHandler {

        private final String host;
        private final int port;
        private final String hub;
        private final byte[] body;
        private Sender link;
        private boolean sent;
        private volatile boolean accepted;

        SendHandler(String host, int port, String hub, byte[] body) {
            this.host = host;
            this.port = port;
            this.hub = hub;
            this.body = body;
        }

        @Override
        public void onReactorInit(Event event) {
            Connection connection = event.getReactor().connectionToHost(host, port, this);
            connection.setContainer("floci-az-activity-log-export");
            connection.open();
            Session session = connection.session();
            session.setProperties(new HashMap<>());
            session.open();
            link = session.sender("activity-log-export");
            Target target = new Target();
            target.setAddress(hub);
            link.setTarget(target);
            link.open();
        }

        @Override
        public void onLinkFlow(Event event) {
            if (sent || link == null || link.getCredit() <= 0) {
                return;
            }
            Message message = Message.Factory.create();
            message.setBody(new Data(new Binary(body)));
            byte[] encoded = AmqpManagementReply.encode(message);
            link.delivery("0".getBytes(StandardCharsets.UTF_8));
            link.send(encoded, 0, encoded.length);
            link.advance();
            sent = true;
        }

        @Override
        public void onDelivery(Event event) {
            Delivery delivery = event.getDelivery();
            if (delivery.getRemoteState() == null) {
                return;
            }
            accepted = delivery.getRemoteState() instanceof Accepted;
            delivery.settle();
            event.getConnection().close();
        }

        @Override
        public void onConnectionRemoteClose(Event event) {
            event.getConnection().close();
            event.getReactor().stop();
        }

        @Override
        public void onConnectionLocalClose(Event event) {
            event.getReactor().stop();
        }

        @Override
        public void onTransportError(Event event) {
            event.getConnection().close();
            event.getReactor().stop();
        }
    }
}
