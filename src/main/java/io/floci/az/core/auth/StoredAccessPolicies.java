package io.floci.az.core.auth;

import io.floci.az.core.SignedIdentifiers.AccessPolicy;
import io.floci.az.core.SignedIdentifiers.SignedIdentifier;
import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * A service SAS completed by the stored access policy it names ({@code si}), as Define a stored access policy
 * describes it: the SAS and the policy each hold some of the start, expiry and permissions, never the same one, and
 * together they hold the expiry and the permissions. The policy is read on every request, so changing or removing it
 * changes or revokes every SAS that names it at once.
 */
public final class StoredAccessPolicies {

    private static final AccessPolicy NO_FIELDS = new AccessPolicy(null, null, null);

    private StoredAccessPolicies() {}

    /**
     * What a service SAS grants once the policy it names has completed it: the completed SAS, or why it is refused.
     */
    public record Grant(StorageSasToken token, Optional<StorageAuthFailure> refusal) {

        static Grant of(StorageSasToken token) {
            return new Grant(token, Optional.empty());
        }

        static Grant refused(String detail) {
            return refused(Optional.of(detail));
        }

        static Grant refused(Optional<String> detail) {
            return new Grant(null, Optional.of(StorageAuthFailure.authenticationFailed(detail)));
        }

        static Grant refused(int status, String detail) {
            return new Grant(null, Optional.of(StorageAuthFailure.authenticationFailed(status, Optional.of(detail))));
        }
    }

    /**
     * Completes {@code token} with the policy of {@code identifiers} it names. A SAS that names none is returned as
     * it is; its time window was checked when it was read.
     *
     * @param identifiers the stored access policies of the container, queue or table the SAS is signed for
     */
    public static Grant complete(StorageSasToken token, List<SignedIdentifier> identifiers) {
        if (token.identifier() == null) {
            return Grant.of(token);
        }
        Optional<AccessPolicy> named = identifiers.stream()
                .filter(identifier -> token.identifier().equals(identifier.id()))
                .findFirst()
                .map(identifier -> identifier.accessPolicy() == null ? NO_FIELDS : identifier.accessPolicy());
        if (named.isEmpty()) {
            return Grant.refused("SAS identifier cannot be found for specified signed identifier");
        }
        String start = blankToNull(named.get().start());
        String expiry = blankToNull(named.get().expiry());
        String permission = blankToNull(named.get().permission());
        if (token.expiryTime() == null && expiry == null) {
            return Grant.refused("Signed expiry must be specified in signature or SAS identifier");
        }
        if (token.permissions() == null && permission == null) {
            return Grant.refused("Signed permission must be specified in signature or SAS identifier");
        }
        if ((token.startTime() != null && start != null) || (token.expiryTime() != null && expiry != null)
                || (token.permissions() != null && permission != null)) {
            // Set Container, Queue and Table ACL: "if a field is specified both in the shared access signature URL and
            // in the stored access policy, the request fails with status code 400 (Bad Request)".
            return Grant.refused(Response.Status.BAD_REQUEST.getStatusCode(),
                    "Access policy fields can be associated with signature or SAS identifier but not both");
        }
        StorageSasToken completed = token.withAccessPolicy(
                start == null ? token.startTime() : start,
                expiry == null ? token.expiryTime() : expiry,
                permission == null ? token.permissions() : permission);
        return completed.isValidAt(Instant.now()) ? Grant.of(completed) : Grant.refused(Optional.empty());
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
