package io.floci.az.services.graph;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * {@code GET /v1.0/auditLogs/directoryAudits} and {@code /auditLogs/directoryAudits/{id}}: the tenant's directory
 * audit log, newest first, at most {@link #MAX_PAGE} per page with an {@code @odata.nextLink} carrying an opaque
 * {@code $skiptoken}.
 */
final class GraphDirectoryAudits {

    /** Graph documents no page size for this list; the sign-in log's 1,000 is used. */
    static final int MAX_PAGE = 1000;

    /** What the handler answers with: a body, or an error code and message. */
    record Outcome(int status, Map<String, Object> body, String errorCode, String message) {
        static Outcome ok(Map<String, Object> body) {
            return new Outcome(200, body, null, null);
        }

        static Outcome error(int status, String code, String message) {
            return new Outcome(status, null, code, message);
        }
    }

    private final DirectoryAuditLog log;
    private final String base;

    /** @param base the {@code v1.0} base of the Graph endpoint of the request's cloud, ending with a slash */
    GraphDirectoryAudits(DirectoryAuditLog log, String base) {
        this.log = log;
        this.base = base;
    }

    Outcome get(String tenantId, String id) {
        Optional<DirectoryAudit> audit = log.get(tenantId, id);
        if (audit.isEmpty()) {
            return Outcome.error(404, "Request_ResourceNotFound", "Resource '" + id + "' does not exist.");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("@odata.context", base + "$metadata#auditLogs/directoryAudits/$entity");
        body.putAll(audit.get().toJson());
        return Outcome.ok(body);
    }

    Outcome list(String tenantId, Map<String, String> query) {
        Predicate<DirectoryAudit> filter;
        try {
            filter = DirectoryAuditFilter.compile(query.get("$filter"));
        } catch (IllegalArgumentException e) {
            return Outcome.error(400, "Request_BadRequest", e.getMessage());
        }
        int top = MAX_PAGE;
        String rawTop = query.get("$top");
        if (rawTop != null) {
            try {
                top = Integer.parseInt(rawTop.trim());
            } catch (NumberFormatException e) {
                top = -1;
            }
            if (top < 1 || top > MAX_PAGE) {
                return Outcome.error(400, "Request_BadRequest", "$top must be between 1 and " + MAX_PAGE + ".");
            }
        }
        boolean ascending;
        String orderBy = query.get("$orderby");
        if (orderBy == null || orderBy.isBlank() || orderBy.trim().matches("(?i)activityDateTime(\\s+desc)?")) {
            ascending = false;
        } else if (orderBy.trim().matches("(?i)activityDateTime\\s+asc")) {
            ascending = true;
        } else {
            return Outcome.error(400, "Request_BadRequest", "Only $orderby=activityDateTime asc or desc is supported.");
        }
        long before;
        int offset;
        String skipToken = query.get("$skiptoken");
        if (skipToken == null) {
            before = log.nextSequence();
            offset = 0;
        } else {
            long[] cursor = cursor(skipToken);
            if (cursor == null) {
                return Outcome.error(400, "Request_BadRequest", "Invalid $skiptoken.");
            }
            before = cursor[0];
            offset = (int) cursor[1];
        }

        List<DirectoryAuditLog.Entry> matching = new ArrayList<>(log.query(tenantId, filter, before));
        if (!ascending) {
            Collections.reverse(matching);
        }
        List<Map<String, Object>> value = new ArrayList<>();
        for (int i = offset; i < matching.size() && value.size() < top; i++) {
            value.add(matching.get(i).audit().toJson());
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("@odata.context", base + "$metadata#auditLogs/directoryAudits");
        int next = offset + value.size();
        if (next < matching.size()) {
            body.put("@odata.nextLink", nextLink(query, token(before, next)));
        }
        body.put("value", value);
        return Outcome.ok(body);
    }

    private String nextLink(Map<String, String> query, String token) {
        StringBuilder link = new StringBuilder(base).append("auditLogs/directoryAudits?");
        for (String name : List.of("$filter", "$top", "$orderby")) {
            String value = query.get(name);
            if (value != null) {
                link.append(name).append('=').append(URLEncoder.encode(value, StandardCharsets.UTF_8)).append('&');
            }
        }
        return link.append("$skiptoken=").append(token).toString();
    }

    private static String token(long before, int offset) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString((before + "_" + offset).getBytes(StandardCharsets.UTF_8));
    }

    private static long[] cursor(String token) {
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
            String[] parts = decoded.split("_");
            if (parts.length != 2) {
                return null;
            }
            long before = Long.parseLong(parts[0]);
            long offset = Long.parseLong(parts[1]);
            return before < 1 || offset < 0 || offset > Integer.MAX_VALUE ? null : new long[]{before, offset};
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
