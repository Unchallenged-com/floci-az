package io.floci.az.services.entra;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.az.core.cloud.CloudCatalog;
import io.floci.az.core.cloud.CloudProfile;
import io.floci.az.services.entra.DirectoryReader.DirectoryApplication;
import io.floci.az.services.entra.DirectoryReader.DirectoryServicePrincipal;
import io.floci.az.services.entra.DirectoryReader.DirectoryUser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

/**
 * Writes the {@link SignInLog} entry of one sign-in from what the endpoint that served it knows: the request, the
 * {@link SignInAttempt} the grant filled in, and the response it answered. A response other than a success is a
 * failed sign-in carrying the AADSTS code and message of its error body.
 */
@ApplicationScoped
public class SignInRecorder {

    private static final Logger LOG = Logger.getLogger(SignInRecorder.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static final String GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";
    static final String GRAPH_DISPLAY_NAME = "Microsoft Graph";
    static final String BROWSER = "Browser";
    static final String DESKTOP_CLIENT = "Mobile Apps and Desktop clients";

    /** The header MSAL and the Azure SDKs send their request id in, which the sign-in log reports as correlation id. */
    static final String CLIENT_REQUEST_ID = "client-request-id";

    private final SignInLog log;
    private final DirectoryReader directory;

    @Inject
    public SignInRecorder(SignInLog log, DirectoryReader directory) {
        this.log = log;
        this.directory = directory;
    }

    /**
     * Records one sign-in.
     *
     * @param request              the token or authorize request
     * @param attempt              who signed in, as far as the grant resolved it
     * @param appId                the client application id
     * @param clientObjectId       the client's service principal object id
     * @param scope                the requested scope (or v1 resource), naming the resource signed in to
     * @param clientCredentialType {@code clientSecret}, {@code clientAssertion} or {@code none}
     * @param clientAppUsed        {@link #BROWSER} or {@link #DESKTOP_CLIENT}
     * @param outcome              the response the endpoint answered
     */
    public void record(EntraRequest request, SignInAttempt attempt, String appId, String clientObjectId, String scope,
                       String clientCredentialType, String clientAppUsed, Response outcome) {
        String tenantId = request.directoryTenantId();
        DirectoryUser user = attempt.user();
        boolean userSignIn = !SignIn.SERVICE_PRINCIPAL.equals(attempt.eventType());
        String upn = userSignIn && attempt.userPrincipalName() != null
                ? attempt.userPrincipalName().toLowerCase(Locale.ROOT) : null;
        String appDisplayName = appDisplayName(tenantId, appId);
        String[] resource = resource(request, tenantId, scope);
        int status = outcome == null ? 500 : outcome.getStatus();
        int errorCode = 0;
        String failureReason = null;
        if (status / 100 != 2 && status / 100 != 3) {
            JsonNode body = errorBody(outcome);
            errorCode = body.path("error_codes").path(0).asInt(0);
            failureReason = failureReason(body.path("error_description").asText(""));
        }
        log.record(new SignIn(UUID.randomUUID().toString(), Instant.now().truncatedTo(ChronoUnit.SECONDS),
                attempt.eventType(),
                userSignIn && user != null ? user.id() : null, upn,
                userSignIn && user != null ? user.displayName() : null, appId, appDisplayName,
                clientObjectId, request.request().remoteAddress(), clientAppUsed, correlationId(request),
                resource[0], resource[1], clientCredentialType, tenantId, errorCode, failureReason));
    }

    private String appDisplayName(String tenantId, String appId) {
        if (appId == null) {
            return null;
        }
        return directory.applicationByAppId(tenantId, appId).map(DirectoryApplication::displayName)
                .or(() -> directory.servicePrincipalByAppId(tenantId, appId).map(DirectoryServicePrincipal::displayName))
                .orElse(null);
    }

    /**
     * The application id and display name of the resource a scope names: Microsoft Graph, or an application of the
     * directory named by its application id or an {@code api://{appId}} URI. Any other resource is unknown to the
     * emulator's directory and reported as null.
     */
    private String[] resource(EntraRequest request, String tenantId, String scope) {
        String named = resourceOf(scope);
        if (named == null) {
            return new String[]{null, null};
        }
        CloudProfile cloud = request.request().scope() == null
                ? CloudCatalog.forNameOrPublic(CloudCatalog.PUBLIC_CLOUD) : request.request().scope().cloud();
        String trimmed = named.endsWith("/") ? named.substring(0, named.length() - 1) : named;
        if (GRAPH_APP_ID.equalsIgnoreCase(trimmed) || cloud.endpoints().microsoftGraph().equalsIgnoreCase(trimmed)) {
            return new String[]{GRAPH_APP_ID, GRAPH_DISPLAY_NAME};
        }
        String appId = trimmed.startsWith("api://") ? trimmed.substring("api://".length()) : trimmed;
        Optional<DirectoryApplication> app = directory.applicationByAppId(tenantId, appId);
        return app.map(a -> new String[]{a.appId(), a.displayName()}).orElse(new String[]{null, null});
    }

    /**
     * The resource of the first scope that is not an OpenID Connect one: the scope itself when it is a bare
     * resource, else the URI without its last segment ({@code https://graph.microsoft.com/User.Read},
     * {@code api://app/.default}).
     */
    static String resourceOf(String scope) {
        if (scope == null || scope.isBlank()) {
            return null;
        }
        for (String value : scope.trim().split("\\s+")) {
            switch (value) {
                case "openid", "profile", "email", "offline_access" -> {
                    continue;
                }
                default -> {
                    int authority = value.indexOf("://");
                    int cut = value.lastIndexOf('/');
                    return authority >= 0 && cut > authority + 2 ? value.substring(0, cut) : value;
                }
            }
        }
        return null;
    }

    private static String correlationId(EntraRequest request) {
        HttpHeaders headers = request.request().headers();
        String sent = headers == null ? null : headers.getHeaderString(CLIENT_REQUEST_ID);
        return sent == null || sent.isBlank() ? UUID.randomUUID().toString() : sent.trim();
    }

    private static JsonNode errorBody(Response outcome) {
        if (outcome == null || !(outcome.getEntity() instanceof String text)) {
            return MAPPER.createObjectNode();
        }
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            LOG.debugv(e, "Entra: sign-in failure without a readable error body");
            return MAPPER.createObjectNode();
        }
    }

    /** The message of an {@code error_description}: what follows {@code AADSTSnnnn: }, up to the trace lines. */
    static String failureReason(String description) {
        String message = description;
        int end = message.indexOf("\r\n");
        if (end >= 0) {
            message = message.substring(0, end);
        }
        if (message.startsWith("AADSTS")) {
            int colon = message.indexOf(": ");
            if (colon >= 0) {
                message = message.substring(colon + 2);
            }
        }
        return message.isBlank() ? null : message;
    }
}
