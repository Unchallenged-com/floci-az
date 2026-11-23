package io.floci.az.core.auth;

import io.floci.az.config.EmulatorConfig;
import io.floci.az.core.AuthContext;
import io.floci.az.core.AuthType;
import io.floci.az.core.AzureRequest;
import io.floci.az.core.SignedIdentifiers.SignedIdentifier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Function;

/**
 * The Queue and Table services' SAS checks, with {@code parity-overrides.strict-storage-keys}; without it, as before,
 * they serve any SAS whose time window is open. {@link SasTokenVerifier} has already checked the time window, an
 * account SAS's signature, and every SAS's {@code sip} and {@code spr}.
 *
 * <ul>
 *   <li>An account SAS must grant the service ({@code ss}), the resource type ({@code srt}) and the permission of
 *       the operation, in that order.</li>
 *   <li>A service SAS must be signed by one of the account's keys over the service's string to sign (Create a
 *       service SAS, version 2015-04-05 and later), name the table the request addresses ({@code tn}), address an
 *       operation a service SAS can grant, and hold its permission. A service SAS that names a stored access
 *       policy ({@code si}) takes the fields it leaves out from the policy of its queue or table.</li>
 * </ul>
 */
@ApplicationScoped
public class QueueTableSasAuthorization {

    /** "Version 2015-04-05 adds support for the signed IP and signed protocol fields", the layout checked here. */
    private static final String FIRST_VERSION = "2015-04-05";

    private final StorageAccountKeys keys;
    private final EmulatorConfig config;

    @Inject
    public QueueTableSasAuthorization(StorageAccountKeys keys, EmulatorConfig config) {
        this.keys = keys;
        this.config = config;
    }

    /**
     * The refusal of the request's SAS for an operation that needs {@code grant}, if any.
     *
     * @param resource the queue or table the request addresses; null for a service-level operation
     * @param policies   the stored access policies of a queue or table, by name, read when a service SAS names one
     */
    public Optional<StorageAuthFailure> authorize(AzureRequest request, String resource, SasGrant grant,
                                                  Function<String, List<SignedIdentifier>> policies) {
        AuthContext context = request.authContext();
        if (!config.strictStorageKeys() || context == null || context.type() != AuthType.SAS
                || context.storageSas().isEmpty()) {
            return Optional.empty();
        }
        StorageSasToken token = context.storageSas().get();
        boolean table = "table".equals(request.serviceType());
        if (token.isAccountSas()) {
            if (token.services().indexOf(table ? 't' : 'q') < 0) {
                return Optional.of(StorageAuthFailure.serviceMismatch());
            }
            if (token.resourceTypes().indexOf(grant.resourceType()) < 0) {
                return Optional.of(StorageAuthFailure.resourceTypeMismatch());
            }
            return SasGrant.grants(grant.accountPermissions(), token.permissions()) ? Optional.empty()
                    : Optional.of(StorageAuthFailure.permissionMismatch());
        }
        // User delegation is Blob-only. A SAS that names a stored access policy may leave sp and se to it.
        if (token.isUserDelegation()
                || (token.identifier() == null && (token.permissions() == null || token.expiryTime() == null))
                || token.version().compareTo(FIRST_VERSION) < 0 || (table && token.tableName() == null)) {
            return Optional.of(StorageAuthFailure.authenticationFailed(Optional.empty()));
        }
        String name = table ? token.tableName() : resource;
        if (name == null) {
            // A queue service SAS signs one queue; the service-level operations are not one.
            return Optional.of(StorageAuthFailure.authorizationFailure());
        }
        String stringToSign = table ? tableStringToSign(request.accountName(), token)
                : queueStringToSign(request.accountName(), name, token);
        if (keys.signer(request.accountName(), stringToSign, token.signature()).isEmpty()) {
            return Optional.of(StorageAuthFailure.authenticationFailed(
                    Optional.of(StorageSasAuthorization.signatureMismatch(stringToSign))));
        }
        StoredAccessPolicies.Grant completed = StoredAccessPolicies.complete(token,
                token.identifier() == null ? List.of() : policies.apply(name));
        if (completed.refusal().isPresent()) {
            return completed.refusal();
        }
        // A table's $batch names no table in its path: the operations it carries are the table's.
        if (grant.servicePermissions().isEmpty() || (resource != null && !resource.equalsIgnoreCase(name))) {
            return Optional.of(StorageAuthFailure.authorizationFailure());
        }
        return SasGrant.grants(grant.servicePermissions(), completed.token().permissions()) ? Optional.empty()
                : Optional.of(StorageAuthFailure.permissionMismatch());
    }

    /** {@code sp st se /queue/<account>/<queue> si sip spr sv}. */
    private static String queueStringToSign(String account, String queue, StorageSasToken token) {
        return String.join("\n", value(token.permissions()), value(token.startTime()), value(token.expiryTime()),
                "/queue/" + account + "/" + queue, value(token.identifier()), value(token.ipRange()),
                value(token.protocol()), value(token.version()));
    }

    /** {@code sp st se /table/<account>/<table> si sip spr sv spk srk epk erk}; "Table names must be lowercase". */
    private static String tableStringToSign(String account, StorageSasToken token) {
        return String.join("\n", value(token.permissions()), value(token.startTime()), value(token.expiryTime()),
                "/table/" + account + "/" + token.tableName().toLowerCase(Locale.ROOT), value(token.identifier()),
                value(token.ipRange()), value(token.protocol()), value(token.version()),
                value(token.startPartitionKey()), value(token.startRowKey()), value(token.endPartitionKey()),
                value(token.endRowKey()));
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }
}
