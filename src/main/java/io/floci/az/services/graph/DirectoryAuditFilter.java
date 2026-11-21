package io.floci.az.services.graph;

import io.floci.az.services.graph.DirectoryAudit.Target;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The {@code $filter} of {@code /auditLogs/directoryAudits}: the comparisons the {@code directoryAudit} reference lists
 * for each property, joined with {@code and}. String comparisons ignore case.
 */
final class DirectoryAuditFilter {

    private static final String STRING = "'((?:[^']|'')*)'";
    private static final Pattern DATE = Pattern.compile(
            "activityDateTime\\s+(eq|ge|le)\\s+'?([0-9][0-9:.TZ+-]*)'?", Pattern.CASE_INSENSITIVE);
    private static final Pattern EQUALS = Pattern.compile("([A-Za-z/]+)\\s+eq\\s+" + STRING, Pattern.CASE_INSENSITIVE);
    private static final Pattern STARTS_WITH = Pattern.compile(
            "startswith\\(\\s*([A-Za-z/]+)\\s*,\\s*" + STRING + "\\s*\\)", Pattern.CASE_INSENSITIVE);
    private static final Pattern TARGETS = Pattern.compile("targetResources/any\\(\\s*(\\w+)\\s*:\\s*(.+)\\)",
            Pattern.CASE_INSENSITIVE);

    /** The properties that take {@code eq}, by their lowercased path. */
    private static final Map<String, Function<DirectoryAudit, String>> EQ = Map.of(
            "id", DirectoryAudit::id,
            "activitydisplayname", DirectoryAudit::activityDisplayName,
            "correlationid", DirectoryAudit::correlationId,
            "loggedbyservice", audit -> DirectoryAudit.LOGGED_BY,
            "initiatedby/user/id", audit -> audit.initiatedBy().user() ? audit.initiatedBy().userId() : null,
            "initiatedby/user/displayname", audit -> audit.initiatedBy().user() ? audit.initiatedBy().userDisplayName() : null,
            "initiatedby/user/userprincipalname",
            audit -> audit.initiatedBy().user() ? audit.initiatedBy().userPrincipalName() : null,
            "initiatedby/app/appid", audit -> audit.initiatedBy().app() ? audit.initiatedBy().appId() : null,
            "initiatedby/app/displayname", audit -> audit.initiatedBy().app() ? audit.initiatedBy().appDisplayName() : null);

    /** The properties that take {@code startswith}. */
    private static final Map<String, Function<DirectoryAudit, String>> STARTS = Map.of(
            "activitydisplayname", DirectoryAudit::activityDisplayName,
            "initiatedby/user/userprincipalname",
            audit -> audit.initiatedBy().user() ? audit.initiatedBy().userPrincipalName() : null);

    private DirectoryAuditFilter() {
    }

    /** Compiles {@code filter}; throws {@link IllegalArgumentException} on a clause the reference does not list. */
    static Predicate<DirectoryAudit> compile(String filter) {
        Predicate<DirectoryAudit> all = audit -> true;
        if (filter == null || filter.isBlank()) {
            return all;
        }
        for (String clause : clauses(filter)) {
            all = all.and(clause(clause));
        }
        return all;
    }

    private static Predicate<DirectoryAudit> clause(String clause) {
        Matcher date = DATE.matcher(clause);
        if (date.matches()) {
            Instant at = instant(date.group(2));
            return switch (date.group(1).toLowerCase(Locale.ROOT)) {
                case "ge" -> audit -> !audit.activityDateTime().isBefore(at);
                case "le" -> audit -> !audit.activityDateTime().isAfter(at);
                default -> audit -> audit.activityDateTime().equals(at);
            };
        }
        Matcher targets = TARGETS.matcher(clause);
        if (targets.matches()) {
            Predicate<Target> target = target(targets.group(1), targets.group(2).trim());
            return audit -> audit.targetResources().stream().anyMatch(target);
        }
        Matcher equals = EQUALS.matcher(clause);
        if (equals.matches()) {
            Function<DirectoryAudit, String> property = EQ.get(equals.group(1).toLowerCase(Locale.ROOT));
            if (property != null) {
                String value = unescape(equals.group(2));
                return audit -> value.equalsIgnoreCase(property.apply(audit));
            }
        }
        Matcher starts = STARTS_WITH.matcher(clause);
        if (starts.matches()) {
            Function<DirectoryAudit, String> property = STARTS.get(starts.group(1).toLowerCase(Locale.ROOT));
            if (property != null) {
                String prefix = unescape(starts.group(2)).toLowerCase(Locale.ROOT);
                return audit -> startsWith(property.apply(audit), prefix);
            }
        }
        throw new IllegalArgumentException("Unsupported filter clause: " + clause);
    }

    /** {@code t/id eq '...'}, {@code t/displayName eq '...'} or {@code startswith(t/displayName,'...')}. */
    private static Predicate<Target> target(String variable, String body) {
        String id = variable.toLowerCase(Locale.ROOT) + "/id";
        String name = variable.toLowerCase(Locale.ROOT) + "/displayname";
        Matcher equals = EQUALS.matcher(body);
        if (equals.matches()) {
            String path = equals.group(1).toLowerCase(Locale.ROOT);
            String value = unescape(equals.group(2));
            if (path.equals(id)) {
                return target -> value.equalsIgnoreCase(target.id());
            }
            if (path.equals(name)) {
                return target -> value.equalsIgnoreCase(target.displayName());
            }
        }
        Matcher starts = STARTS_WITH.matcher(body);
        if (starts.matches() && starts.group(1).toLowerCase(Locale.ROOT).equals(name)) {
            String prefix = unescape(starts.group(2)).toLowerCase(Locale.ROOT);
            return target -> startsWith(target.displayName(), prefix);
        }
        throw new IllegalArgumentException("Unsupported targetResources filter: " + body);
    }

    private static boolean startsWith(String value, String lowercasePrefix) {
        return value != null && value.toLowerCase(Locale.ROOT).startsWith(lowercasePrefix);
    }

    private static Instant instant(String value) {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Invalid activityDateTime value: " + value, e);
        }
    }

    private static String unescape(String literal) {
        return literal.replace("''", "'");
    }

    /** Splits on {@code and} outside quotes and parentheses, and drops the parentheses that wrap a whole clause. */
    static List<String> clauses(String filter) {
        List<String> parts = new ArrayList<>();
        int depth = 0;
        boolean quoted = false;
        int start = 0;
        String lower = filter.toLowerCase(Locale.ROOT);
        for (int i = 0; i < filter.length(); i++) {
            char c = filter.charAt(i);
            if (c == '\'') {
                quoted = !quoted;
            } else if (!quoted && c == '(') {
                depth++;
            } else if (!quoted && c == ')') {
                depth--;
            } else if (!quoted && depth == 0 && lower.startsWith(" and ", i)) {
                parts.add(filter.substring(start, i));
                start = i + " and ".length();
                i = start - 1;
            }
        }
        parts.add(filter.substring(start));
        List<String> clauses = new ArrayList<>();
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                throw new IllegalArgumentException("Empty filter clause");
            }
            if (trimmed.startsWith("(") && trimmed.endsWith(")") && wraps(trimmed)) {
                clauses.addAll(clauses(trimmed.substring(1, trimmed.length() - 1)));
            } else {
                clauses.add(trimmed);
            }
        }
        return clauses;
    }

    /** Whether the opening parenthesis of {@code clause} closes at its last character. */
    private static boolean wraps(String clause) {
        int depth = 0;
        boolean quoted = false;
        for (int i = 0; i < clause.length(); i++) {
            char c = clause.charAt(i);
            if (c == '\'') {
                quoted = !quoted;
            } else if (!quoted && c == '(') {
                depth++;
            } else if (!quoted && c == ')') {
                depth--;
                if (depth == 0 && i < clause.length() - 1) {
                    return false;
                }
            }
        }
        return true;
    }
}
