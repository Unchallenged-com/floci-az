package io.floci.az.services.entra;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One Microsoft Entra sign-in, in the {@code signIn} shape Microsoft Graph serves at {@code /auditLogs/signIns}.
 *
 * @param id                   unique id of the sign-in
 * @param createdDateTime      when the sign-in was initiated, to the second as Graph reports it
 * @param eventType            {@code interactiveUser}, {@code nonInteractiveUser} or {@code servicePrincipal}
 * @param userId               the user's object id; null for a service principal sign-in or an unknown user
 * @param userPrincipalName    the user principal name as signed in with, lowercased; null for a service principal
 * @param userDisplayName      the user's display name, or null
 * @param appId                the client application id
 * @param appDisplayName       the client application's display name, or null when the directory has none
 * @param servicePrincipalId   the client's service principal object id, for a service principal sign-in
 * @param ipAddress            the client's address as the emulator saw it
 * @param clientAppUsed        {@code Browser} for the authorize endpoint, else {@code Mobile Apps and Desktop clients}
 * @param correlationId        the {@code client-request-id} the client sent, or one made up for it
 * @param resourceId           the application id of the resource signed in to, or null when unknown
 * @param resourceDisplayName  the resource's display name, or null when unknown
 * @param clientCredentialType {@code clientSecret}, {@code clientAssertion} or {@code none}
 * @param tenantId             the tenant of the sign-in
 * @param errorCode            {@code 0} on success, else the AADSTS code the token endpoint answered
 * @param failureReason        the AADSTS message of a failure, else null
 */
public record SignIn(String id, Instant createdDateTime, String eventType, String userId, String userPrincipalName,
                     String userDisplayName, String appId, String appDisplayName, String servicePrincipalId,
                     String ipAddress, String clientAppUsed, String correlationId, String resourceId,
                     String resourceDisplayName, String clientCredentialType, String tenantId, int errorCode,
                     String failureReason) {

    public static final String INTERACTIVE_USER = "interactiveUser";
    public static final String NON_INTERACTIVE_USER = "nonInteractiveUser";
    public static final String SERVICE_PRINCIPAL = "servicePrincipal";

    public boolean isInteractive() {
        return INTERACTIVE_USER.equals(eventType);
    }

    private boolean userSignIn() {
        return !SERVICE_PRINCIPAL.equals(eventType);
    }

    /**
     * The sign-in as Graph serialises it: the v1.0 {@code signIn} properties, plus the beta ones
     * ({@code signInEventTypes}, the service principal, credential and tenant properties) when {@code beta}.
     * Conditional Access, risk, device and location are not modelled and carry the values of a sign-in that none
     * of them applied to.
     */
    public Map<String, Object> toJson(boolean beta) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("id", id);
        json.put("createdDateTime", createdDateTime.toString());
        json.put("userDisplayName", userDisplayName);
        json.put("userPrincipalName", userPrincipalName);
        json.put("userId", userId);
        json.put("appId", appId);
        json.put("appDisplayName", appDisplayName);
        json.put("ipAddress", ipAddress);
        json.put("clientAppUsed", clientAppUsed);
        json.put("correlationId", correlationId);
        json.put("conditionalAccessStatus", "notApplied");
        json.put("isInteractive", isInteractive());
        json.put("riskDetail", "none");
        json.put("riskLevelAggregated", "none");
        json.put("riskLevelDuringSignIn", "none");
        json.put("riskState", "none");
        json.put("riskEventTypes", List.of());
        json.put("riskEventTypes_v2", List.of());
        json.put("resourceDisplayName", resourceDisplayName);
        json.put("resourceId", resourceId);
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("errorCode", errorCode);
        status.put("failureReason", failureReason);
        status.put("additionalDetails", null);
        json.put("status", status);
        Map<String, Object> device = new LinkedHashMap<>();
        device.put("deviceId", "");
        device.put("displayName", null);
        device.put("operatingSystem", null);
        device.put("browser", null);
        device.put("isCompliant", null);
        device.put("isManaged", null);
        device.put("trustType", null);
        json.put("deviceDetail", device);
        Map<String, Object> location = new LinkedHashMap<>();
        location.put("city", null);
        location.put("state", null);
        location.put("countryOrRegion", null);
        location.put("geoCoordinates", null);
        json.put("location", location);
        json.put("appliedConditionalAccessPolicies", new ArrayList<>());
        if (beta) {
            json.put("signInEventTypes", List.of(eventType));
            json.put("servicePrincipalId", userSignIn() ? "" : servicePrincipalId);
            json.put("servicePrincipalName", userSignIn() ? null : appDisplayName);
            json.put("clientCredentialType", clientCredentialType);
            json.put("homeTenantId", userSignIn() ? tenantId : null);
            json.put("resourceTenantId", tenantId);
            json.put("userType", userSignIn() ? "member" : null);
            json.put("crossTenantAccessType", "none");
        }
        return json;
    }
}
