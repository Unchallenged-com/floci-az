package io.floci.az.services.graph;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One Microsoft Entra audit log entry, in the {@code directoryAudit} shape Microsoft Graph serves at
 * {@code /auditLogs/directoryAudits}.
 *
 * @param id                  unique id of the entry
 * @param activityDateTime    when the change was made
 * @param activityDisplayName the activity, named as the Entra audit activity reference names it
 * @param category            {@code ApplicationManagement} or {@code GroupManagement}
 * @param correlationId       shared by the entries one request wrote
 * @param initiatedBy         who made the change
 * @param operationType       {@code Add}, {@code Assign}, {@code Update}, {@code Unassign} or {@code Delete}
 * @param targetResources     what the change was made to
 * @param additionalDetails   key and value pairs, in order
 */
record DirectoryAudit(String id, Instant activityDateTime, String activityDisplayName, String category,
                      String correlationId, Initiator initiatedBy, String operationType, List<Target> targetResources,
                      List<Map.Entry<String, String>> additionalDetails) {

    static final String LOGGED_BY = "Core Directory";

    /** The user, or else the application, the request's token names; neither for a request without a token. */
    record Initiator(String userId, String userDisplayName, String userPrincipalName, String ipAddress,
                     String appId, String appDisplayName, String servicePrincipalId, boolean user) {

        static final Initiator NONE = new Initiator(null, null, null, null, null, null, null, false);

        boolean app() {
            return !user && (appId != null || servicePrincipalId != null);
        }
    }

    /** A directory object the change was made to, with the properties it changed, values JSON-encoded. */
    record Target(String id, String displayName, String type, String userPrincipalName, List<Modified> modifiedProperties) {
    }

    record Modified(String displayName, String oldValue, String newValue) {
    }

    Map<String, Object> toJson() {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("id", id);
        json.put("category", category);
        json.put("correlationId", correlationId);
        json.put("result", "success");
        json.put("resultReason", "");
        json.put("activityDisplayName", activityDisplayName);
        json.put("activityDateTime", activityDateTime.toString());
        json.put("loggedByService", LOGGED_BY);
        json.put("operationType", operationType);
        Map<String, Object> initiator = new LinkedHashMap<>();
        Map<String, Object> app = null;
        if (initiatedBy.app()) {
            app = new LinkedHashMap<>();
            app.put("appId", initiatedBy.appId());
            app.put("displayName", initiatedBy.appDisplayName());
            app.put("servicePrincipalId", initiatedBy.servicePrincipalId());
            app.put("servicePrincipalName", null);
        }
        Map<String, Object> user = null;
        if (initiatedBy.user()) {
            user = new LinkedHashMap<>();
            user.put("id", initiatedBy.userId());
            user.put("displayName", initiatedBy.userDisplayName());
            user.put("userPrincipalName", initiatedBy.userPrincipalName());
            user.put("ipAddress", initiatedBy.ipAddress());
        }
        initiator.put("app", app);
        initiator.put("user", user);
        json.put("initiatedBy", initiator);
        List<Map<String, Object>> targets = new ArrayList<>();
        for (Target target : targetResources) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("id", target.id());
            out.put("displayName", target.displayName());
            out.put("type", target.type());
            out.put("userPrincipalName", target.userPrincipalName());
            out.put("groupType", null);
            List<Map<String, Object>> modified = new ArrayList<>();
            for (Modified property : target.modifiedProperties()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("displayName", property.displayName());
                m.put("oldValue", property.oldValue());
                m.put("newValue", property.newValue());
                modified.add(m);
            }
            out.put("modifiedProperties", modified);
            targets.add(out);
        }
        json.put("targetResources", targets);
        List<Map<String, Object>> details = new ArrayList<>();
        for (Map.Entry<String, String> detail : additionalDetails) {
            Map<String, Object> d = new LinkedHashMap<>();
            d.put("key", detail.getKey());
            d.put("value", detail.getValue());
            details.add(d);
        }
        json.put("additionalDetails", details);
        return json;
    }
}
