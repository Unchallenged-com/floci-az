package io.floci.az.services.graph;

import io.floci.az.core.Resettable;
import jakarta.enterprise.context.ApplicationScoped;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * The tenant's directory audit log: one {@link DirectoryAudit} per directory change Graph made, kept in memory,
 * oldest dropped beyond {@link #CAPACITY}.
 */
@ApplicationScoped
public class DirectoryAuditLog implements Resettable {

    static final int CAPACITY = 10_000;

    /** An entry with the sequence number that orders it, which page cursors refer to. */
    record Entry(long sequence, String tenantId, DirectoryAudit audit) {
    }

    private final Deque<Entry> entries = new ArrayDeque<>();
    private long nextSequence = 1;

    synchronized void record(String tenantId, DirectoryAudit audit) {
        if (entries.size() >= CAPACITY) {
            entries.removeFirst();
        }
        entries.addLast(new Entry(nextSequence++, tenantId, audit));
    }

    /** The entries of {@code tenantId} that satisfy {@code filter}, oldest first, recorded before {@code before}. */
    synchronized List<Entry> query(String tenantId, Predicate<DirectoryAudit> filter, long before) {
        List<Entry> out = new ArrayList<>();
        for (Entry entry : entries) {
            if (entry.sequence() < before && tenantId.equalsIgnoreCase(entry.tenantId()) && filter.test(entry.audit())) {
                out.add(entry);
            }
        }
        return out;
    }

    synchronized Optional<DirectoryAudit> get(String tenantId, String id) {
        return entries.stream().filter(e -> tenantId.equalsIgnoreCase(e.tenantId()) && e.audit().id().equals(id))
                .map(Entry::audit).findFirst();
    }

    /** The sequence number the next entry will get; a first page reads everything before it. */
    synchronized long nextSequence() {
        return nextSequence;
    }

    @Override
    public synchronized void clear() {
        entries.clear();
    }
}
