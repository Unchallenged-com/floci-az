package io.floci.az.services.graph;

import io.floci.az.services.entra.SignIn;
import io.floci.az.services.entra.SignInLog;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * {@code GET /{v1.0|beta}/auditLogs/signIns} and {@code /auditLogs/signIns/{id}}: the tenant's sign-in log, newest
 * first, at most 1,000 per page with an {@code @odata.nextLink} carrying an opaque {@code $skiptoken}.
 */
final class GraphSignIns {

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

    private final SignInLog log;
    private final String graphRoot;
    private final String version;

    /**
     * @param graphRoot the Graph endpoint of the request's cloud, without a version
     * @param version   {@code v1.0} or {@code beta}
     */
    GraphSignIns(SignInLog log, String graphRoot, String version) {
        this.log = log;
        this.graphRoot = graphRoot;
        this.version = version;
    }

    private boolean beta() {
        return "beta".equals(version);
    }

    Outcome get(String tenantId, String id) {
        Optional<SignIn> signIn = log.get(tenantId, id);
        if (signIn.isEmpty()) {
            return Outcome.error(404, "Request_ResourceNotFound", "Resource '" + id + "' does not exist.");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("@odata.context", graphRoot + "/" + version + "/$metadata#auditLogs/signIns/$entity");
        body.putAll(signIn.get().toJson(beta()));
        return Outcome.ok(body);
    }

    Outcome list(String tenantId, Map<String, String> query) {
        SignInFilter filter;
        try {
            filter = SignInFilter.compile(query.get("$filter"), beta());
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
        if (orderBy == null || orderBy.isBlank() || orderBy.trim().matches("(?i)createdDateTime(\\s+desc)?")) {
            ascending = false;
        } else if (orderBy.trim().matches("(?i)createdDateTime\\s+asc")) {
            ascending = true;
        } else {
            return Outcome.error(400, "Request_BadRequest", "Only $orderby=createdDateTime asc or desc is supported.");
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

        List<SignInLog.Entry> matching = new ArrayList<>(log.query(tenantId, filter.predicate(), before));
        if (!ascending) {
            Collections.reverse(matching);
        }
        List<Map<String, Object>> value = new ArrayList<>();
        for (int i = offset; i < matching.size() && value.size() < top; i++) {
            value.add(matching.get(i).signIn().toJson(beta()));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("@odata.context", graphRoot + "/" + version + "/$metadata#auditLogs/signIns");
        int next = offset + value.size();
        if (next < matching.size()) {
            body.put("@odata.nextLink", nextLink(query, token(before, next)));
        }
        body.put("value", value);
        return Outcome.ok(body);
    }

    private String nextLink(Map<String, String> query, String token) {
        StringBuilder link = new StringBuilder(graphRoot).append('/').append(version).append("/auditLogs/signIns?");
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
