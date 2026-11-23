package io.floci.az.core.auth;

import io.floci.az.config.EmulatorConfig;
import io.floci.az.core.AuthContext;
import io.floci.az.core.AuthType;
import io.floci.az.core.AzureRequest;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Instant;
import java.util.Optional;

/**
 * Reads a SAS from the query and checks its time window. An account SAS to a storage service is also checked against
 * the account's keys: the key that signed it is recorded, and with {@code parity-overrides.strict-storage-keys} one
 * no current key signed is refused. With the switch, any SAS to a storage service must also allow the caller's
 * address ({@code sip}) and protocol ({@code spr}). The Blob service checks every SAS it serves, signature included,
 * in {@link StorageSasAuthorization}; the Queue and Table services check a service SAS's signature and every SAS's
 * permissions in {@link QueueTableSasAuthorization}. A service SAS that names a stored access policy leaves its
 * window to the policy, and is checked again once the policy has completed it ({@link StoredAccessPolicies}).
 */
@ApplicationScoped
public class SasTokenVerifier implements AuthVerifier {

    private final StorageAccountKeys keys;
    private final EmulatorConfig config;

    @Inject
    public SasTokenVerifier(StorageAccountKeys keys, EmulatorConfig config) {
        this.keys = keys;
        this.config = config;
    }

    @Override
    public Optional<AuthContext> verify(AzureRequest request) {
        return StorageSasToken.from(request.queryParams())
            .map(sas -> {
                boolean valid = sas.isValidAt(Instant.now());
                boolean storage = SharedKeyAuthVerifier.STORAGE_SERVICES.contains(request.serviceType())
                        && request.accountName() != null;
                Optional<String> signer = Optional.empty();
                Optional<StorageAuthFailure> failure = Optional.empty();
                if (storage && sas.isAccountSas()) {
                    String stringToSign = sas.accountStringToSign(request.accountName());
                    signer = keys.signer(request.accountName(), stringToSign, sas.signature());
                    if (signer.isEmpty() && config.strictStorageKeys()) {
                        failure = Optional.of(StorageAuthFailure.authenticationFailed(
                                Optional.of(StorageSasAuthorization.signatureMismatch(stringToSign))));
                    }
                }
                if (valid && failure.isEmpty() && storage && config.strictStorageKeys()) {
                    failure = addressFailure(request, sas);
                }
                return new AuthContext(request.accountName(), AuthType.SAS, valid && failure.isEmpty(),
                        Optional.of(sas), signer, failure);
            });
    }

    /**
     * The refusal of a SAS whose {@code sip} does not cover the caller, or whose {@code spr} is {@code https} for a
     * request over HTTP. "Only IPv4 addresses are supported", so an IPv6 caller never matches a {@code sip}.
     */
    private static Optional<StorageAuthFailure> addressFailure(AzureRequest request, StorageSasToken sas) {
        String caller = request.remoteAddress() == null ? "" : request.remoteAddress();
        if (sas.ipRange() != null && !inRange(caller, sas.ipRange())) {
            return Optional.of(StorageAuthFailure.sourceIpMismatch(caller));
        }
        if ("https".equals(sas.protocol()) && !request.secure()) {
            return Optional.of(StorageAuthFailure.protocolMismatch());
        }
        return Optional.empty();
    }

    /** Whether {@code address} is the single IPv4 address {@code range} names, or inside its inclusive "a-b" range. */
    static boolean inRange(String address, String range) {
        long caller = ipv4(address);
        int dash = range.indexOf('-');
        long low = ipv4(dash < 0 ? range : range.substring(0, dash));
        long high = dash < 0 ? low : ipv4(range.substring(dash + 1));
        return caller >= 0 && low >= 0 && high >= 0 && caller >= low && caller <= high;
    }

    /** The IPv4 address as an unsigned number, or -1 when it is not one. */
    private static long ipv4(String text) {
        String[] parts = text.trim().split("\\.", -1);
        if (parts.length != 4) {
            return -1;
        }
        long value = 0;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !part.chars().allMatch(Character::isDigit)) {
                return -1;
            }
            int octet = Integer.parseInt(part);
            if (octet > 255) {
                return -1;
            }
            value = value * 256 + octet;
        }
        return value;
    }
}
