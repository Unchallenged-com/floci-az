package io.floci.az.services.graph;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.floci.az.core.AzureRequest;
import io.floci.az.core.auth.BearerClaims;
import io.floci.az.services.entra.DirectoryEntitySet;
import io.floci.az.services.entra.DirectoryObject;
import io.floci.az.services.entra.GraphDirectoryStore;
import io.floci.az.services.graph.DirectoryAudit.Initiator;
import io.floci.az.services.graph.DirectoryAudit.Modified;
import io.floci.az.services.graph.DirectoryAudit.Target;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Writes the directory audit entries of one Graph request, under the activity names and categories of the Entra audit
 * activity reference ({@code Core Directory}). Every entry of the request shares its correlation id and initiator: the
 * user, or else the application, its bearer token names. Only changes that were made are logged.
 *
 * <p>Modified properties carry the property names and value encodings Entra writes: a JSON array of the values for
 * an object's own properties ({@code "[\"name\"]"}, {@code "[]"} for none), a JSON string for the
 * {@code Group.*} and {@code Application.*} properties of a membership or ownership entry, and an
 * {@code Included Updated Properties} entry listing the properties changed.
 */
final class DirectoryAuditor {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String APPLICATIONS = "ApplicationManagement";
    private static final String GROUPS = "GroupManagement";
    private static final String ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private final DirectoryAuditLog log;
    private final GraphDirectoryStore store;
    private final String tenantId;
    private final AzureRequest request;
    private final SecureRandom random;
    private final String correlationId = UUID.randomUUID().toString();
    private Initiator initiator;

    DirectoryAuditor(DirectoryAuditLog log, GraphDirectoryStore store, String tenantId, AzureRequest request,
                     SecureRandom random) {
        this.log = log;
        this.store = store;
        this.tenantId = tenantId;
        this.request = request;
        this.random = random;
    }

    void addApplication(DirectoryObject app) {
        record("Add application", APPLICATIONS, "Add", app.text("appId"), List.of(new Target(app.id(),
                app.text("displayName"), "Application", null, List.of(
                        added("AppId", app.text("appId")), added("DisplayName", app.text("displayName")),
                        included("AppId", "DisplayName")))));
    }

    void addServicePrincipal(DirectoryObject sp) {
        String appId = sp.text("appId");
        record("Add service principal", APPLICATIONS, "Add", appId, List.of(new Target(sp.id(), sp.text("displayName"),
                "ServicePrincipal", null, List.of(
                        new Modified("AccountEnabled", "[]", "[true]"), added("AppPrincipalId", appId),
                        added("DisplayName", sp.text("displayName")), added("ServicePrincipalName", appId),
                        included("AccountEnabled", "AppPrincipalId", "DisplayName", "ServicePrincipalName"),
                        new Modified("TargetId.ServicePrincipalNames", null, string(appId))))));
    }

    /** The registration after an update; {@code before} is its display name before. */
    void updateApplication(String before, DirectoryObject app) {
        List<Modified> modified = new ArrayList<>();
        String after = app.text("displayName");
        if (!after.equals(before)) {
            modified.add(new Modified("DisplayName", array(before), array(after)));
            modified.add(included("DisplayName"));
        }
        record("Update application", APPLICATIONS, "Update", app.text("appId"),
                List.of(new Target(app.id(), after, "Application", null, modified)));
    }

    /** A client secret added or removed: the registration's password credentials before and after. */
    void secrets(DirectoryObject app, JsonNode before, JsonNode after) {
        record("Update application - Certificates and secrets management", APPLICATIONS, "Update", app.text("appId"),
                List.of(new Target(app.id(), app.text("displayName"), "Application", null, List.of(
                        new Modified("KeyDescription", keys(before), keys(after)), included("KeyDescription")))));
    }

    void deleteApplication(DirectoryObject app) {
        record("Delete application", APPLICATIONS, "Delete", app.text("appId"),
                List.of(new Target(app.id(), app.text("displayName"), "Application", null, List.of())));
    }

    void removeServicePrincipal(DirectoryObject sp) {
        record("Remove service principal", APPLICATIONS, "Delete", sp.text("appId"),
                List.of(new Target(sp.id(), sp.text("displayName"), "ServicePrincipal", null, List.of())));
    }

    void addOwner(DirectoryObject app, DirectoryObject owner) {
        ownership("Add owner to application", "Assign", app, owner, true);
    }

    void removeOwner(DirectoryObject app, DirectoryObject owner) {
        ownership("Remove owner from application", "Unassign", app, owner, false);
    }

    void addMember(DirectoryObject group, DirectoryObject member) {
        membership("Add member to group", "Assign", group, member, true);
    }

    void removeMember(DirectoryObject group, DirectoryObject member) {
        membership("Remove member from group", "Unassign", group, member, false);
    }

    private void ownership(String activity, String operation, DirectoryObject app, DirectoryObject owner, boolean add) {
        String name = string(app.text("displayName"));
        Modified property = new Modified("Application.DisplayName", add ? null : name, add ? name : null);
        record(activity, APPLICATIONS, operation, app.text("appId"), List.of(principal(owner, List.of(property)),
                new Target(app.id(), app.text("displayName"), "Application", null, List.of())));
    }

    private void membership(String activity, String operation, DirectoryObject group, DirectoryObject member,
                            boolean add) {
        String id = string(group.id());
        String name = string(group.text("displayName"));
        List<Modified> properties = List.of(
                new Modified("Group.ObjectID", add ? null : id, add ? id : null),
                new Modified("Group.DisplayName", add ? null : name, add ? name : null));
        record(activity, GROUPS, operation, null, List.of(principal(member, properties),
                new Target(group.id(), group.text("displayName"), "Group", null, List.of())));
    }

    private static Target principal(DirectoryObject object, List<Modified> properties) {
        String type = switch (object.entitySet()) {
            case "users" -> "User";
            case "groups" -> "Group";
            default -> "ServicePrincipal";
        };
        return new Target(object.id(), object.text("displayName"), type,
                "User".equals(type) ? object.text("userPrincipalName") : null, properties);
    }

    /** {@code AppId} detail: the application id of the application the entry is about, as Entra records it. */
    private void record(String activity, String category, String operationType, String appId, List<Target> targets) {
        List<Map.Entry<String, String>> details = new ArrayList<>();
        String userAgent = request.headers() == null ? null : request.headers().getHeaderString("User-Agent");
        if (userAgent != null) {
            details.add(Map.entry("User-Agent", userAgent));
        }
        if (appId != null) {
            details.add(Map.entry("AppId", appId));
        }
        log.record(tenantId, new DirectoryAudit(id(), Instant.now(), activity, category, correlationId, initiator(),
                operationType, targets, details));
    }

    /** {@code Directory_{correlationId}_{random}_{number}}, the form of the ids Core Directory gives its entries. */
    private String id() {
        StringBuilder suffix = new StringBuilder();
        for (int i = 0; i < 5; i++) {
            suffix.append(ID_ALPHABET.charAt(random.nextInt(ID_ALPHABET.length())));
        }
        return "Directory_" + correlationId + "_" + suffix + "_" + (10_000_000 + random.nextInt(90_000_000));
    }

    private Initiator initiator() {
        if (initiator == null) {
            initiator = resolve();
        }
        return initiator;
    }

    private Initiator resolve() {
        BearerClaims claims = BearerClaims.of(request);
        if (!claims.present()) {
            return Initiator.NONE;
        }
        if ("User".equals(claims.principalType())) {
            String displayName = claims.oid() == null ? null
                    : store.get(tenantId, DirectoryEntitySet.USERS, claims.oid()).map(u -> u.text("displayName")).orElse(null);
            return new Initiator(claims.oid(), displayName, claims.upn(), request.remoteAddress(), null, null, null, true);
        }
        String displayName = claims.appId() == null ? null
                : store.findByAlternateKey(tenantId, DirectoryEntitySet.SERVICE_PRINCIPALS, "appId", claims.appId())
                        .map(sp -> sp.text("displayName")).orElse(null);
        return new Initiator(null, null, null, null, claims.appId(), displayName, claims.oid(), false);
    }

    private static Modified added(String name, String value) {
        return new Modified(name, "[]", array(value));
    }

    private static Modified included(String... names) {
        return new Modified("Included Updated Properties", null, string(String.join(", ", names)));
    }

    /**
     * The {@code KeyDescription} value of a set of password credentials: one
     * {@code [KeyIdentifier=...,KeyType=Password,KeyUsage=Verify,DisplayName=...]} string per secret.
     */
    private static String keys(JsonNode credentials) {
        List<String> keys = new ArrayList<>();
        if (credentials != null) {
            for (JsonNode credential : credentials) {
                String displayName = credential.path("displayName").isTextual() ? credential.path("displayName").asText() : "";
                keys.add("[KeyIdentifier=" + credential.path("keyId").asText() + ",KeyType=Password,KeyUsage=Verify,DisplayName="
                        + displayName + "]");
            }
        }
        return json(keys);
    }

    private static String array(String value) {
        return value == null ? "[]" : json(List.of(value));
    }

    private static String string(String value) {
        return json(value);
    }

    private static String json(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
