package io.floci.az.services.entra;

import io.floci.az.services.entra.DirectoryReader.DirectoryUser;

/**
 * What a sign-in log entry needs to know about one sign-in while it is being served: who signs in, which is only
 * known once a grant has resolved the user (from the username, the authorization code or the refresh token).
 * The token endpoint creates one per request and hands it to the grant through {@link TokenRequest#signIn()}.
 */
public final class SignInAttempt {

    private final String eventType;
    private String userPrincipalName;
    private DirectoryUser user;

    public SignInAttempt(String eventType) {
        this.eventType = eventType;
    }

    /** The sign-in event type: a user sign-in, interactive or not, or a service principal sign-in. */
    public String eventType() {
        return eventType;
    }

    /** The name the user signed in with, before the directory resolved it (or when it could not). */
    public void userPrincipalName(String name) {
        this.userPrincipalName = name;
    }

    /** The directory user the grant resolved. */
    public void user(DirectoryUser resolved) {
        this.user = resolved;
    }

    public DirectoryUser user() {
        return user;
    }

    public String userPrincipalName() {
        return user != null ? user.userPrincipalName() : userPrincipalName;
    }
}
