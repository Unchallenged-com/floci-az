package io.floci.az.services.entra;

import io.floci.az.core.Resettable;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * The tenant sign-in log: one {@link SignIn} per token request the token endpoint answered and per approval the
 * authorize endpoint gave, kept in memory, oldest dropped beyond {@link #CAPACITY}. Graph reads it at
 * {@code /auditLogs/signIns}.
 */
@ApplicationScoped
public class SignInLog implements Resettable {

    static final int CAPACITY = 10_000;

    /** A sign-in with the sequence number that orders it, which page cursors refer to. */
    public record Entry(long sequence, SignIn signIn) {
    }

    private final Deque<Entry> entries = new ArrayDeque<>();
    private long nextSequence = 1;

    public synchronized void record(SignIn signIn) {
        if (entries.size() >= CAPACITY) {
            entries.removeFirst();
        }
        entries.addLast(new Entry(nextSequence++, signIn));
    }

    /**
     * The sign-ins of {@code tenantId} that satisfy {@code filter}, oldest first, recorded before the sequence
     * number {@code before}, so that a page cursor stays stable while new sign-ins arrive.
     */
    public synchronized List<Entry> query(String tenantId, Predicate<SignIn> filter, long before) {
        List<Entry> out = new ArrayList<>();
        for (Entry entry : entries) {
            if (entry.sequence() < before && tenantId.equalsIgnoreCase(entry.signIn().tenantId())
                    && filter.test(entry.signIn())) {
                out.add(entry);
            }
        }
        return out;
    }

    public synchronized Optional<SignIn> get(String tenantId, String id) {
        return entries.stream().map(Entry::signIn)
                .filter(signIn -> signIn.id().equalsIgnoreCase(id) && tenantId.equalsIgnoreCase(signIn.tenantId()))
                .findFirst();
    }

    /** The sequence number the next sign-in will get; a first page reads everything before it. */
    public synchronized long nextSequence() {
        return nextSequence;
    }

    @Override
    public synchronized void clear() {
        entries.clear();
    }
}
