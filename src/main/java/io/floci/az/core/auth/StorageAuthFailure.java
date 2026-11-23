package io.floci.az.core.auth;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * A refusal (403, unless noted) a storage data plane answers a request whose credentials it cannot verify ({@code AuthenticationFailed}) or
 * whose SAS does not grant it (the SAS error codes), in the shape Azure answers it: the message ends with the request
 * id and the time, and an {@code AuthenticationFailed} XML body carries an {@code AuthenticationErrorDetail} that
 * says what failed. The response carries the {@code x-ms-request-id} the message names.
 *
 * @param status the HTTP status
 * @param detail the {@code AuthenticationErrorDetail}, for {@code AuthenticationFailed} only
 */
public record StorageAuthFailure(int status, String code, String message, Optional<String> detail) {

    private static final String NOT_AUTHORIZED = "This request is not authorized to perform this operation";
    /** Azure's {@code Time:} line: UTC with seven fractional digits. */
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSSS'Z'");

    public static StorageAuthFailure authenticationFailed(Optional<String> detail) {
        return authenticationFailed(Response.Status.FORBIDDEN.getStatusCode(), detail);
    }

    /** {@code AuthenticationFailed} with another status than 403, where the documentation names one. */
    public static StorageAuthFailure authenticationFailed(int status, Optional<String> detail) {
        return new StorageAuthFailure(status, "AuthenticationFailed", "Server failed to authenticate the request. "
                + "Make sure the value of Authorization header is formed correctly including the signature.", detail);
    }

    /** A SAS whose {@code sip} does not cover the caller's address. */
    public static StorageAuthFailure sourceIpMismatch(String sourceIp) {
        return mismatch("AuthorizationSourceIPMismatch", " using this source IP " + sourceIp + ".");
    }

    /** A SAS whose {@code spr} does not allow the request's protocol. */
    public static StorageAuthFailure protocolMismatch() {
        return mismatch("AuthorizationProtocolMismatch", " using this protocol.");
    }

    public static StorageAuthFailure permissionMismatch() {
        return mismatch("AuthorizationPermissionMismatch", " using this permission.");
    }

    public static StorageAuthFailure serviceMismatch() {
        return mismatch("AuthorizationServiceMismatch", " using this service.");
    }

    public static StorageAuthFailure resourceTypeMismatch() {
        return mismatch("AuthorizationResourceTypeMismatch", " using this resource type.");
    }

    /** "Other authorization errors", such as an operation a service SAS can never grant. */
    public static StorageAuthFailure authorizationFailure() {
        return mismatch("AuthorizationFailure", ".");
    }

    private static StorageAuthFailure mismatch(String code, String ending) {
        return new StorageAuthFailure(Response.Status.FORBIDDEN.getStatusCode(), code, NOT_AUTHORIZED + ending,
                Optional.empty());
    }

    /** The Blob and Queue services' XML error. */
    public Response xml() {
        String requestId = UUID.randomUUID().toString();
        StringBuilder body = new StringBuilder("<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>")
                .append(code).append("</Code><Message>").append(text(message(requestId)))
                .append("</Message>");
        detail.ifPresent(value -> body.append("<AuthenticationErrorDetail>").append(text(value))
                .append("</AuthenticationErrorDetail>"));
        body.append("</Error>");
        return response(requestId).type(MediaType.APPLICATION_XML).entity(body.toString()).build();
    }

    /** The Table service's OData error, which has no field for the detail. */
    public Response odata() {
        String requestId = UUID.randomUUID().toString();
        return response(requestId).type("application/json;odata=minimalmetadata")
                .entity(Map.of("odata.error", Map.of(
                        "code", code,
                        "message", Map.of("lang", "en-US", "value", message(requestId)))))
                .build();
    }

    /** XML text as the service writes it: quotes, which the detail's string to sign holds, are left as they are. */
    private static String text(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private Response.ResponseBuilder response(String requestId) {
        return Response.status(status)
                .header("x-ms-error-code", code)
                .header("x-ms-request-id", requestId);
    }

    private String message(String requestId) {
        return message + "\nRequestId:" + requestId + "\nTime:" + TIME.format(ZonedDateTime.now(ZoneOffset.UTC));
    }
}
