package io.floci.az.services.policy.evaluation;

import io.floci.az.core.arm.ArmCall;
import io.floci.az.core.directory.AzureDirectory;
import io.floci.az.services.managementgroups.ManagementGroupStore;
import io.floci.az.services.monitor.activitylog.ActivityLog;
import io.floci.az.services.monitor.activitylog.ActivityLogRule;
import io.floci.az.services.policy.evaluation.PolicyEngine.Match;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Writes the Activity Log's {@code Policy} entry for an effect that fired on a write: one
 * {@code Microsoft.Authorization/policies/{effect}/action} entry per effect, in the operation of the write it judged,
 * naming every definition that produced it. Only the effects Azure records there: {@code deny} and {@code audit}.
 */
@ApplicationScoped
public class PolicyActivity {

    private final ActivityLog log;
    private final ActivityLogRule operations;
    private final ManagementGroupStore managementGroups;
    private final AzureDirectory directory;

    @Inject
    public PolicyActivity(ActivityLog log, ActivityLogRule operations, ManagementGroupStore managementGroups,
                          AzureDirectory directory) {
        this.log = log;
        this.operations = operations;
        this.managementGroups = managementGroups;
        this.directory = directory;
    }

    /** The operation {@code call} belongs to, captured while it is in flight; empty when the Activity Log is off. */
    Optional<ActivityLog.RequestFacts> operation(ArmCall call) {
        return operations.operation(call);
    }

    /** Records {@code effect} ({@code deny} or {@code audit}) for {@code matches}, in the operation {@code facts}. */
    void record(Optional<ActivityLog.RequestFacts> facts, ArmCall call, String effect, List<Match> matches,
                Map<String, Object> content) {
        if (facts.isEmpty() || matches.isEmpty()) {
            return;
        }
        List<Map<String, Object>> policies = new ArrayList<>();
        for (Match match : matches) {
            policies.add(policy(match));
        }
        String location = content != null && content.get("location") instanceof String l ? l : null;
        log.recordPolicyEffect(facts.get(), effect, policies, location, ancestors(call));
    }

    /**
     * The definition that fired, with the keys an exported Policy entry carries, in its order; the initiative's and the
     * versions only when there are any.
     */
    static Map<String, Object> policy(Match match) {
        Map<String, Object> definition = PolicyEngine.properties(match.definition());
        Map<String, Object> assignment = PolicyEngine.properties(match.assignment());
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("policyDefinitionId", match.definition().get("id"));
        if (match.setDefinition() != null) {
            Map<String, Object> set = PolicyEngine.properties(match.setDefinition());
            policy.put("policySetDefinitionId", match.setDefinition().get("id"));
            policy.put("policyDefinitionReferenceId", match.referenceId());
            policy.put("policySetDefinitionName", match.setDefinition().get("name"));
            policy.put("policySetDefinitionDisplayName", set.get("displayName"));
            if (set.get("version") instanceof String version) {
                policy.put("policySetDefinitionVersion", version);
            }
        }
        policy.put("policyDefinitionName", match.definition().get("name"));
        policy.put("policyDefinitionDisplayName", definition.get("displayName"));
        if (definition.get("version") instanceof String version) {
            policy.put("policyDefinitionVersion", version);
        }
        policy.put("policyDefinitionEffect", effectName(match.effect()));
        policy.put("policyAssignmentId", match.assignment().get("id"));
        policy.put("policyAssignmentName", match.assignment().get("name"));
        policy.put("policyAssignmentDisplayName", assignment.get("displayName"));
        policy.put("policyAssignmentScope", assignment.get("scope"));
        policy.put("policyAssignmentParameters", PolicyEngine.parameterValues(assignment.get("parameters")));
        policy.put("policyExemptionIds", List.of());
        policy.put("policyEnrollmentIds", List.of());
        return policy;
    }

    /** {@code Deny}, {@code Audit}: the effect as the Activity Log spells it. */
    static String effectName(String effect) {
        return effect == null || effect.isEmpty() ? effect
            : effect.substring(0, 1).toUpperCase(Locale.ROOT) + effect.substring(1);
    }

    /** The management groups above the written resource's subscription, from its parent to the tenant root. */
    private List<String> ancestors(ArmCall call) {
        String subscriptionId = call.id() == null ? null : call.id().subscriptionId();
        if (subscriptionId == null) {
            return List.of();
        }
        String tenantId = directory.tenantOfSubscription(subscriptionId);
        ManagementGroupStore.Group parent = managementGroups.parentOf(tenantId, subscriptionId);
        List<String> names = new ArrayList<>();
        names.add(parent.name());
        for (ManagementGroupStore.Group ancestor : managementGroups.ancestors(tenantId, parent.name())) {
            names.add(ancestor.name());
        }
        return names;
    }
}
