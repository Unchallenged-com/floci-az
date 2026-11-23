package io.floci.az.core.auth;

import java.util.Arrays;
import java.util.List;

/**
 * What a Queue or Table operation needs from a SAS. An account SAS must name the resource type and one of the
 * account permission sets (Create an account SAS, the Queue and Table service operation tables); a service SAS must
 * hold one of the service permission sets (Create a service SAS, the queue and table permission tables). A set is
 * the letters it needs together: {@code au} for an upsert, "Add (a) and Update (u)".
 *
 * @param resourceType          {@code s} for the service, {@code c} for a queue or table, {@code o} for messages
 *                              and entities
 * @param accountPermissions    the account SAS permission sets, any one of which grants the operation
 * @param servicePermissions    the service SAS permission sets; empty when "a service SAS can't grant access" to it
 */
public record SasGrant(char resourceType, List<String> accountPermissions, List<String> servicePermissions) {

    /** A grant from {@code |}-separated permission sets, {@code ""} for none: {@code of('c', "c|w", "")}. */
    public static SasGrant of(char resourceType, String accountPermissions, String servicePermissions) {
        return new SasGrant(resourceType, sets(accountPermissions), sets(servicePermissions));
    }

    /** "Other authorization errors (for example, attempting to modify an access control list)": no SAS grants it. */
    public static SasGrant none(char resourceType) {
        return new SasGrant(resourceType, List.of(), List.of());
    }

    private static List<String> sets(String permissions) {
        return permissions.isEmpty() ? List.of() : Arrays.asList(permissions.split("\\|"));
    }

    /** Whether {@code permissions} holds every letter of one of {@code sets}. */
    static boolean grants(List<String> sets, String permissions) {
        String held = permissions == null ? "" : permissions;
        return sets.stream().anyMatch(set -> set.chars().allMatch(letter -> held.indexOf(letter) >= 0));
    }
}
