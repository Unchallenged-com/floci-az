package io.floci.az.services.graph;

import io.floci.az.services.entra.SignIn;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The {@code $filter} of {@code /auditLogs/signIns}: the comparisons the {@code signIn} reference lists for each
 * property, joined with {@code and}. Beta also takes {@code signInEventTypes/any(t: t eq '...')}, without which only
 * interactive sign-ins are listed, as on Azure.
 */
final class SignInFilter {

    private static final String STRING = "'((?:[^']|'')*)'";
    private static final Pattern DATE = Pattern.compile(
            "createdDateTime\\s+(eq|ge|le)\\s+'?([0-9][0-9:.TZ+-]*)'?", Pattern.CASE_INSENSITIVE);
    private static final Pattern EQUALS = Pattern.compile("([A-Za-z]+)\\s+eq\\s+" + STRING, Pattern.CASE_INSENSITIVE);
    private static final Pattern ERROR_CODE = Pattern.compile("status/errorCode\\s+eq\\s+(\\d+)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern STARTS_WITH = Pattern.compile("startswith\\(\\s*([A-Za-z]+)\\s*,\\s*" + STRING + "\\s*\\)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern EVENT_TYPES = Pattern.compile(
            "signInEventTypes/any\\(\\s*(\\w+)\\s*:\\s*(.+)\\)", Pattern.CASE_INSENSITIVE);
    private static final Set<String> EVENT_TYPE_VALUES =
            Set.of(SignIn.INTERACTIVE_USER, SignIn.NON_INTERACTIVE_USER, SignIn.SERVICE_PRINCIPAL, "managedIdentity");

    /** The string properties that take {@code eq}, by their lowercased name. */
    private static final Map<String, Function<SignIn, String>> EQ_PROPERTIES = Map.ofEntries(
            Map.entry("id", SignIn::id), Map.entry("userid", SignIn::userId),
            Map.entry("userprincipalname", SignIn::userPrincipalName),
            Map.entry("userdisplayname", SignIn::userDisplayName), Map.entry("appid", SignIn::appId),
            Map.entry("appdisplayname", SignIn::appDisplayName), Map.entry("ipaddress", SignIn::ipAddress),
            Map.entry("correlationid", SignIn::correlationId), Map.entry("clientappused", SignIn::clientAppUsed),
            Map.entry("resourceid", SignIn::resourceId), Map.entry("resourcedisplayname", SignIn::resourceDisplayName),
            Map.entry("conditionalaccessstatus", signIn -> "notApplied"));

    /** The string properties that take {@code startsWith}. */
    private static final Map<String, Function<SignIn, String>> STARTS_WITH_PROPERTIES = Map.of(
            "appdisplayname", SignIn::appDisplayName, "userprincipalname", SignIn::userPrincipalName,
            "userdisplayname", SignIn::userDisplayName, "ipaddress", SignIn::ipAddress);

    private final Predicate<SignIn> predicate;

    private SignInFilter(Predicate<SignIn> predicate) {
        this.predicate = predicate;
    }

    Predicate<SignIn> predicate() {
        return predicate;
    }

    /**
     * Compiles {@code filter}; {@code beta} allows {@code signInEventTypes}. Throws {@link IllegalArgumentException}
     * on anything else.
     */
    static SignInFilter compile(String filter, boolean beta) {
        Predicate<SignIn> all = signIn -> true;
        Set<String> eventTypes = null;
        if (filter != null && !filter.isBlank()) {
            for (String clause : clauses(filter)) {
                Matcher types = EVENT_TYPES.matcher(clause);
                if (beta && types.matches()) {
                    eventTypes = eventTypes(types.group(1), types.group(2));
                    continue;
                }
                all = all.and(clause(clause));
            }
        }
        Set<String> listed = eventTypes == null ? Set.of(SignIn.INTERACTIVE_USER) : eventTypes;
        return new SignInFilter(all.and(signIn -> listed.contains(signIn.eventType())));
    }

    private static Predicate<SignIn> clause(String clause) {
        Matcher date = DATE.matcher(clause);
        if (date.matches()) {
            Instant at = instant(date.group(2));
            return switch (date.group(1).toLowerCase(Locale.ROOT)) {
                case "ge" -> signIn -> !signIn.createdDateTime().isBefore(at);
                case "le" -> signIn -> !signIn.createdDateTime().isAfter(at);
                default -> signIn -> signIn.createdDateTime().equals(at);
            };
        }
        Matcher code = ERROR_CODE.matcher(clause);
        if (code.matches()) {
            int expected = Integer.parseInt(code.group(1));
            return signIn -> signIn.errorCode() == expected;
        }
        Matcher equals = EQUALS.matcher(clause);
        if (equals.matches()) {
            Function<SignIn, String> property = EQ_PROPERTIES.get(equals.group(1).toLowerCase(Locale.ROOT));
            if (property != null) {
                String value = unescape(equals.group(2));
                return signIn -> value.equalsIgnoreCase(property.apply(signIn));
            }
        }
        Matcher startsWith = STARTS_WITH.matcher(clause);
        if (startsWith.matches()) {
            Function<SignIn, String> property = STARTS_WITH_PROPERTIES.get(startsWith.group(1).toLowerCase(Locale.ROOT));
            if (property != null) {
                String prefix = unescape(startsWith.group(2)).toLowerCase(Locale.ROOT);
                return signIn -> property.apply(signIn) != null
                        && property.apply(signIn).toLowerCase(Locale.ROOT).startsWith(prefix);
            }
        }
        throw new IllegalArgumentException("Unsupported filter clause: " + clause);
    }

    private static Set<String> eventTypes(String variable, String body) {
        Set<String> out = new LinkedHashSet<>();
        Pattern one = Pattern.compile("\\s*" + Pattern.quote(variable) + "\\s+eq\\s+" + STRING + "\\s*");
        for (String alternative : body.split("(?i)\\s+or\\s+")) {
            Matcher matcher = one.matcher(alternative);
            if (!matcher.matches() || !EVENT_TYPE_VALUES.contains(matcher.group(1))) {
                throw new IllegalArgumentException("Unsupported signInEventTypes filter: " + body);
            }
            out.add(matcher.group(1));
        }
        return out;
    }

    private static Instant instant(String value) {
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("Invalid createdDateTime value: " + value, e);
        }
    }

    private static String unescape(String literal) {
        return literal.replace("''", "'");
    }

    /** Splits on {@code and} outside quotes and parentheses, and drops the parentheses that wrap a whole clause. */
    static List<String> clauses(String filter) {
        List<String> out = new ArrayList<>();
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
                out.add(filter.substring(start, i));
                start = i + " and ".length();
                i = start - 1;
            }
        }
        out.add(filter.substring(start));
        List<String> clauses = new ArrayList<>();
        for (String clause : out) {
            String trimmed = clause.trim();
            if (trimmed.startsWith("(") && trimmed.endsWith(")") && wraps(trimmed)) {
                clauses.addAll(clauses(trimmed.substring(1, trimmed.length() - 1)));
            } else if (!trimmed.isEmpty()) {
                clauses.add(trimmed);
            } else {
                throw new IllegalArgumentException("Empty filter clause");
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
