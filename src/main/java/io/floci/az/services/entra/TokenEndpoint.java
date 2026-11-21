package io.floci.az.services.entra;

import io.floci.az.config.EmulatorConfig;
import io.floci.az.core.FormBody;
import io.floci.az.services.entra.DirectoryReader.DirectoryApplication;
import io.floci.az.services.entra.DirectoryReader.DirectoryServicePrincipal;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * {@code POST /{tenant}/oauth2/v2.0/token} and the v1.0 {@code POST /{tenant}/oauth2/token}.
 * Resolves what every grant shares (tenant, client, issuer, lifetime), authenticates the client
 * through {@link ClientAuthenticator} and dispatches on {@code grant_type} to the registered
 * {@link GrantHandler}s; any other grant type is answered with
 * {@link AadstsError#UNSUPPORTED_GRANT_TYPE}.
 */
@ApplicationScoped
public class TokenEndpoint implements EntraEndpoint {

    private static final String V2_PATH = "oauth2/v2.0/token";
    private static final String V1_PATH = "oauth2/token";

    /**
     * Client authentication methods the endpoint accepts: a secret in the form, a secret in HTTP
     * Basic, and a {@code client_assertion} (accepted unverified). Secrets are checked only when
     * {@code entra.validate-client-credentials} is on; either way the client is identified from the
     * form, or from the HTTP Basic user when the form names none.
     */
    private static final List<String> AUTH_METHODS =
            List.of("client_secret_post", "client_secret_basic", "private_key_jwt");

    private final EmulatorConfig config;
    private final DirectoryReader directory;
    private final IssuerFactory issuers;
    private final EntraResponses responses;
    private final ClientAuthenticator authenticator;
    private final Map<String, GrantHandler> grants;
    private final SignInRecorder signIns;

    @Inject
    public TokenEndpoint(EmulatorConfig config, DirectoryReader directory, IssuerFactory issuers,
                         EntraResponses responses, ClientAuthenticator authenticator,
                         Instance<GrantHandler> grantHandlers, SignInRecorder signIns) {
        this.config = config;
        this.directory = directory;
        this.issuers = issuers;
        this.responses = responses;
        this.authenticator = authenticator;
        this.grants = indexByGrantType(grantHandlers);
        this.signIns = signIns;
    }

    private static Map<String, GrantHandler> indexByGrantType(Iterable<GrantHandler> handlers) {
        Map<String, GrantHandler> byType = new TreeMap<>();
        for (GrantHandler handler : handlers) {
            GrantHandler previous = byType.put(handler.grantType(), handler);
            if (previous != null) {
                throw new IllegalStateException("Two Entra grant handlers claim grant_type '"
                        + handler.grantType() + "'");
            }
        }
        return byType;
    }

    /** The registered grant types, in a stable (sorted) order. */
    public List<String> grantTypes() {
        return List.copyOf(grants.keySet());
    }

    @Override
    public boolean matches(String path) {
        return path.endsWith(V2_PATH) || path.endsWith(V1_PATH);
    }

    @Override
    public void advertise(EntraRequest request, Map<String, Object> document) {
        document.put("token_endpoint", request.tenantBase() + "/" + V2_PATH);
        document.put("token_endpoint_auth_methods_supported", AUTH_METHODS);
        document.put("grant_types_supported", grantTypes());
    }

    @Override
    public Response handle(EntraRequest request) {
        Map<String, String> form = FormBody.parse(request.request().bodyStream());
        String grantType = form.getOrDefault("grant_type", "");
        GrantHandler grant = grants.get(grantType);
        if (grant == null) {
            return responses.error(AadstsError.UNSUPPORTED_GRANT_TYPE, grantType);
        }
        ClientCredentials credentials = ClientCredentials.from(form, authorizationHeader(request));
        TokenRequest tokenRequest = tokenRequest(request, form, credentials, new SignInAttempt(eventType(grantType)));
        if ("password".equals(grantType)) {
            tokenRequest.signIn().userPrincipalName(form.get("username"));
        }
        Optional<ClientAuthenticator.Rejection> rejection =
                authenticator.authenticate(credentials, request.tenant(), grant.requiresClientCredential());
        Response response = rejection.isPresent()
                ? responses.error(rejection.get().error(), rejection.get().argArray())
                : grant.handle(tokenRequest);
        signIns.record(request, tokenRequest.signIn(), tokenRequest.appId(), tokenRequest.clientObjectId(),
                tokenRequest.scope(), clientCredentialType(credentials), SignInRecorder.DESKTOP_CLIENT, response);
        return response;
    }

    /**
     * The sign-in event type of a grant: a password is an authentication factor the user provides, so an interactive
     * sign-in; a code or refresh token redeemed for the user is a non-interactive one; an app's own credential is a
     * service principal sign-in.
     */
    private static String eventType(String grantType) {
        return switch (grantType) {
            case "password" -> SignIn.INTERACTIVE_USER;
            case "client_credentials" -> SignIn.SERVICE_PRINCIPAL;
            default -> SignIn.NON_INTERACTIVE_USER;
        };
    }

    private static String clientCredentialType(ClientCredentials credentials) {
        if (credentials.assertion()) {
            return "clientAssertion";
        }
        return credentials.clientSecret() != null ? "clientSecret" : "none";
    }

    private static String authorizationHeader(EntraRequest request) {
        HttpHeaders headers = request.request().headers();
        return headers == null ? null : headers.getHeaderString(HttpHeaders.AUTHORIZATION);
    }

    private TokenRequest tokenRequest(EntraRequest request, Map<String, String> form, ClientCredentials credentials,
                                      SignInAttempt signIn) {
        boolean v2 = request.path().endsWith(V2_PATH);
        String clientId = credentials.clientId();
        String scope = form.getOrDefault("scope", form.get("resource"));
        String directoryTenantId = request.directoryTenantId();
        DirectoryApplication app = clientId == null
                ? null
                : directory.applicationByAppId(directoryTenantId, clientId).orElse(null);

        String appId = app != null ? app.appId() : (clientId != null ? clientId : EntraStore.DEV_CLIENT_ID);
        String clientObjectId = app != null
                ? directory.servicePrincipalByAppId(directoryTenantId, appId).map(DirectoryServicePrincipal::id)
                        .orElse(app.id())
                : TokenIssuer.deterministicGuid(appId);

        return new TokenRequest(form, request.tenantId(), directoryTenantId, request.baseUrl(), v2, clientId, appId,
                clientObjectId, issuers.issuer(request.baseUrl(), request.tenantId(), v2), scope,
                config.services().entra().tokenLifetimeSeconds(),
                credentials.clientSecret() != null || credentials.assertion(), signIn);
    }
}
