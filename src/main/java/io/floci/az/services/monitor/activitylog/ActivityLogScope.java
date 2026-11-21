package io.floci.az.services.monitor.activitylog;

import java.util.Locale;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Which Activity Log a list operation reads: a subscription's; the tenant's, which holds only the entries generated
 * outside any subscription (management groups, the tenant root); or a management group's, the tenant entries
 * scoped to that group.
 *
 * @param subscriptionId    the subscription, for a subscription log
 * @param managementGroupId the group, for a management-group log
 */
public record ActivityLogScope(String subscriptionId, String managementGroupId) {

    private static final String VALUES = "providers/microsoft\\.insights/eventtypes/management/values";
    private static final Pattern TENANT = Pattern.compile("(?i)^/?" + VALUES + "/?$");
    private static final Pattern MANAGEMENT_GROUP = Pattern.compile(
            "(?i)^/?providers/microsoft\\.management/managementgroups/([^/]+)/" + VALUES + "/?$");
    private static final String MANAGEMENT_GROUPS = "/providers/microsoft.management/managementgroups/";

    public static ActivityLogScope subscription(String subscriptionId) {
        return new ActivityLogScope(subscriptionId, null);
    }

    public static ActivityLogScope tenant() {
        return new ActivityLogScope(null, null);
    }

    /**
     * The tenant or management-group scope a list path names, without its query string; empty for any other path,
     * a subscription's log included.
     */
    public static Optional<ActivityLogScope> outsideSubscriptions(String path) {
        int query = path.indexOf('?');
        String resource = query >= 0 ? path.substring(0, query) : path;
        if (TENANT.matcher(resource).matches()) {
            return Optional.of(tenant());
        }
        Matcher group = MANAGEMENT_GROUP.matcher(resource);
        return group.matches() ? Optional.of(new ActivityLogScope(null, group.group(1))) : Optional.empty();
    }

    /** The entries this log holds. */
    Predicate<ActivityLogEvent> holds() {
        if (subscriptionId != null) {
            return event -> subscriptionId.equalsIgnoreCase(event.subscriptionId());
        }
        if (managementGroupId == null) {
            return event -> event.subscriptionId() == null;
        }
        String prefix = MANAGEMENT_GROUPS + managementGroupId.toLowerCase(Locale.ROOT);
        return event -> {
            if (event.subscriptionId() != null || event.resourceId() == null) {
                return false;
            }
            String id = event.resourceId().toLowerCase(Locale.ROOT);
            return id.equals(prefix) || id.startsWith(prefix + "/");
        };
    }

    /** The list operation's path, for {@code nextLink}. */
    String path() {
        String values = "/providers/microsoft.insights/eventtypes/management/values";
        if (subscriptionId != null) {
            return "/subscriptions/" + subscriptionId + values;
        }
        return managementGroupId == null ? values
                : "/providers/Microsoft.Management/managementGroups/" + managementGroupId + values;
    }
}
