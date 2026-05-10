package com.example.burp.apiauthvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.http.message.params.HttpParameter.parameter;

public final class RequestUtils {
    private static final Pattern JSON_FIELD = Pattern.compile("\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"\\s*:\\s*(\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"|-?\\d+(?:\\.\\d+)?|true|false|null|\\{\\}|\\[\\])");
    private static final Set<String> SELECTED_HEADERS = Set.of(
            "x-api-key", "x-auth-token", "x-csrf-token", "x-requested-with", "x-user-id", "x-tenant-id", "x-account-id"
    );

    private RequestUtils() {
    }

    public static boolean isInScope(MontoyaApi api, HttpRequest request, ScanConfig config) {
        if (config.useBurpScope()) {
            return api.scope().isInScope(request.url());
        }
        return host(request).equalsIgnoreCase(config.targetDomain());
    }

    public static String host(HttpRequest request) {
        try {
            return URI.create(request.url()).getHost() == null ? "" : URI.create(request.url()).getHost();
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    public static boolean isApiLike(HttpRequest request) {
        String path = path(request).toLowerCase(Locale.ROOT);
        String accept = headerValue(request, "Accept").orElse("").toLowerCase(Locale.ROOT);
        String contentType = headerValue(request, "Content-Type").orElse("").toLowerCase(Locale.ROOT);
        return path.contains("/api/")
                || path.endsWith(".json")
                || accept.contains("json")
                || contentType.contains("json")
                || contentType.contains("x-www-form-urlencoded")
                || contentType.contains("multipart/form-data");
    }

    public static boolean isSafeForActiveTesting(HttpRequest request, ScanConfig config) {
        if (config.allowUnsafeMethods()) {
            return true;
        }
        String method = request.method().toUpperCase(Locale.ROOT);
        return method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS");
    }

    public static boolean isRefreshEndpoint(HttpRequest request, ScanConfig config) {
        if (request == null) {
            return false;
        }
        String pattern = config.refreshEndpointPattern();
        if (pattern == null || pattern.isBlank()) {
            return false;
        }
        String url = request.url();
        try {
            return Pattern.compile(pattern).matcher(url).find();
        } catch (Exception ignored) {
            return url.contains(pattern);
        }
    }

    public static String path(HttpRequest request) {
        try {
            String rawPath = URI.create(request.url()).getRawPath();
            return rawPath == null || rawPath.isBlank() ? "/" : rawPath;
        } catch (IllegalArgumentException e) {
            return "/";
        }
    }

    public static String endpoint(HttpRequest request) {
        return host(request) + path(request);
    }

    public static String dedupeKey(HttpRequest request) {
        Set<String> paramNames = new HashSet<>();
        for (HttpParameter parameter : request.parameters()) {
            paramNames.add(parameter.name() + ":" + parameter.type());
        }
        paramNames.addAll(jsonFields(request.bodyToString()).keySet());
        String contentType = headerValue(request, "Content-Type").orElse("").split(";", 2)[0].toLowerCase(Locale.ROOT);
        return request.method().toUpperCase(Locale.ROOT) + " " + path(request) + " " + contentType + " " + String.join(",", paramNames);
    }

    public static Optional<String> headerValue(HttpRequest request, String headerName) {
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase(headerName)) {
                return Optional.ofNullable(header.value());
            }
        }
        return Optional.empty();
    }

    public static Optional<String> extractJsonStringField(String body, String fieldName) {
        if (body == null || body.isBlank() || fieldName == null || fieldName.isBlank()) {
            return Optional.empty();
        }
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*\"([^\"\\\\]*(?:\\\\.[^\"\\\\]*)*)\"");
        Matcher matcher = pattern.matcher(body);
        if (matcher.find()) {
            return Optional.of(unescapeJson(matcher.group(1)));
        }
        return Optional.empty();
    }

    public static String responseHeaderValue(HttpResponse response, String headerName) {
        for (HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase(headerName)) {
                return header.value();
            }
        }
        return "";
    }

    public static HttpRequest removeHeader(HttpRequest request, String headerName) {
        HttpRequest updated = request;
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase(headerName)) {
                updated = updated.withRemovedHeader(header);
            }
        }
        return updated;
    }

    public static HttpRequest replaceHeader(HttpRequest request, String headerName, String value) {
        return removeHeader(request, headerName).withAddedHeader(headerName, value);
    }

    public static List<String> selectedHeaderNames(HttpRequest request, String authHeaderName) {
        List<String> result = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            String name = header.name().toLowerCase(Locale.ROOT);
            if (SELECTED_HEADERS.contains(name) && !header.name().equalsIgnoreCase(authHeaderName)) {
                result.add(header.name());
            }
        }
        return result;
    }

    public static Map<String, String> jsonFields(String body) {
        Map<String, String> fields = new LinkedHashMap<>();
        if (body == null || body.isBlank()) {
            return fields;
        }
        Matcher matcher = JSON_FIELD.matcher(body);
        while (matcher.find()) {
            fields.put(unescapeJson(matcher.group(1)), matcher.group(2));
        }
        return fields;
    }

    public static HttpRequest replaceJsonField(HttpRequest request, String fieldName, String value) {
        String body = request.bodyToString();
        Matcher matcher = JSON_FIELD.matcher(body);
        StringBuffer updated = new StringBuffer();
        boolean replaced = false;
        while (matcher.find()) {
            if (!replaced && unescapeJson(matcher.group(1)).equals(fieldName)) {
                String replacement = "\"" + matcher.group(1) + "\":\"" + escapeJson(value) + "\"";
                matcher.appendReplacement(updated, Matcher.quoteReplacement(replacement));
                replaced = true;
            }
        }
        matcher.appendTail(updated);
        return replaced ? request.withBody(ByteArray.byteArray(updated.toString())) : request;
    }

    public static HttpRequest addJsonFields(HttpRequest request, Map<String, String> additions) {
        String body = request.bodyToString().trim();
        if (!body.startsWith("{") || !body.endsWith("}")) {
            return request;
        }
        StringBuilder injected = new StringBuilder(body.substring(0, body.length() - 1).trim());
        if (injected.length() > 1 && injected.charAt(injected.length() - 1) != '{') {
            injected.append(',');
        }
        int i = 0;
        for (Map.Entry<String, String> entry : additions.entrySet()) {
            if (i++ > 0) {
                injected.append(',');
            }
            injected.append('"').append(escapeJson(entry.getKey())).append('"').append(':').append(entry.getValue());
        }
        injected.append('}');
        return request.withBody(ByteArray.byteArray(injected.toString()));
    }

    public static boolean looksJson(HttpRequest request) {
        String contentType = headerValue(request, "Content-Type").orElse("").toLowerCase(Locale.ROOT);
        String body = request.bodyToString().trim();
        return contentType.contains("json") || (body.startsWith("{") && body.endsWith("}"));
    }

    public static boolean looksForm(HttpRequest request) {
        String contentType = headerValue(request, "Content-Type").orElse("").toLowerCase(Locale.ROOT);
        return contentType.contains("application/x-www-form-urlencoded");
    }

    public static List<ParsedHttpParameter> queryParameters(HttpRequest request) {
        return request.parameters().stream().filter(p -> p.type() == HttpParameterType.URL).toList();
    }

    public static List<ParsedHttpParameter> formParameters(HttpRequest request) {
        return request.parameters().stream().filter(p -> p.type() == HttpParameterType.BODY).toList();
    }

    public static HttpRequest replaceParameter(HttpRequest request, HttpParameter original, String value) {
        return request.withUpdatedParameters(parameter(original.name(), value, original.type()));
    }

    public static HttpRequest addFormFields(HttpRequest request, Map<String, String> additions) {
        HttpRequest updated = request;
        for (Map.Entry<String, String> addition : additions.entrySet()) {
            updated = updated.withAddedParameters(parameter(addition.getKey(), addition.getValue(), HttpParameterType.BODY));
        }
        return updated;
    }

    public static boolean responseHasServerError(HttpResponse response) {
        return response.statusCode() >= 500;
    }

    public static boolean containsErrorPattern(String body) {
        String lower = body.toLowerCase(Locale.ROOT);
        return lower.contains("stack trace")
                || lower.contains("exception")
                || lower.contains("traceback")
                || lower.contains("sql syntax")
                || lower.contains("mysql")
                || lower.contains("postgres")
                || lower.contains("ora-")
                || lower.contains("warning:")
                || lower.contains("java.lang.")
                || lower.contains("validation failed")
                || lower.contains("deserialization");
    }

    public static boolean containsSensitiveJsonKey(String body) {
        String lower = body.toLowerCase(Locale.ROOT);
        return lower.contains("\"token\"")
                || lower.contains("\"access_token\"")
                || lower.contains("\"refresh_token\"")
                || lower.contains("\"password\"")
                || lower.contains("\"secret\"")
                || lower.contains("\"role\"")
                || lower.contains("\"isadmin\"")
                || lower.contains("\"permissions\"");
    }

    public static boolean reflectsPayload(String body, String payload) {
        return body != null && payload != null && !payload.isBlank() && body.contains(payload);
    }

    public static double similarity(String a, String b) {
        if (a == null || b == null) {
            return 0.0;
        }
        if (a.equals(b)) {
            return 1.0;
        }
        Set<String> left = tokenSet(a);
        Set<String> right = tokenSet(b);
        if (left.isEmpty() || right.isEmpty()) {
            return 0.0;
        }
        Set<String> intersection = new HashSet<>(left);
        intersection.retainAll(right);
        Set<String> union = new HashSet<>(left);
        union.addAll(right);
        return (double) intersection.size() / union.size();
    }

    public static boolean differsMeaningfully(Baseline baseline, HttpResponse response) {
        int lengthDelta = Math.abs(response.body().length() - baseline.responseLength());
        return response.statusCode() != baseline.statusCode()
                || lengthDelta > Math.max(250, baseline.responseLength() / 5)
                || response.bodyToString().hashCode() != baseline.bodyHash();
    }

    public static String snippet(String value, int max) {
        if (value == null) {
            return "";
        }
        String cleaned = value.replace("\r", "").replace("\n", "\\n");
        return cleaned.length() <= max ? cleaned : cleaned.substring(0, max) + "...";
    }

    public static String requestSnippet(HttpRequest request) {
        return request.toString();
    }

    public static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : bytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            return Integer.toHexString(value.hashCode());
        }
    }

    public static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    public static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static Set<String> tokenSet(String value) {
        String[] tokens = value.toLowerCase(Locale.ROOT).split("[^a-z0-9_]+");
        Set<String> result = new HashSet<>();
        for (String token : tokens) {
            if (token.length() > 2) {
                result.add(token);
            }
        }
        return result;
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String unescapeJson(String value) {
        return value.replace("\\\"", "\"").replace("\\\\", "\\");
    }
}
