package com.example.burp.apiauthvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class AuthTester {
    private final MontoyaApi api;

    public AuthTester(MontoyaApi api) {
        this.api = api;
    }

    public List<Finding> test(HttpRequest original, Baseline baseline, ScanConfig config) {
        List<Finding> findings = new ArrayList<>();
        if (config.authHeaderName().isBlank() || RequestUtils.headerValue(original, config.authHeaderName()).isEmpty()) {
            return List.of(new Finding(
                    RequestUtils.endpoint(original),
                    original.method(),
                    "Authentication Removal",
                    "Info",
                    baseline.statusCode(),
                    baseline.statusCode(),
                    "Header: " + config.authHeaderName(),
                    "(auth header not present)",
                    "Authentication removal was not performed because the configured auth header was not present in this request.",
                    RequestUtils.requestSnippet(original),
                    baseline.responseSnippet(),
                    "Confirm the configured auth header name matches the application traffic."
            ));
        }
        if (!config.authHeaderValuePattern().isBlank()) {
            String value = RequestUtils.headerValue(original, config.authHeaderName()).orElse("");
            if (!Pattern.compile(config.authHeaderValuePattern()).matcher(value).find()) {
                return List.of(new Finding(
                        RequestUtils.endpoint(original),
                        original.method(),
                        "Authentication Removal",
                        "Info",
                        baseline.statusCode(),
                        baseline.statusCode(),
                        "Header: " + config.authHeaderName(),
                        "(auth header value did not match configured regex)",
                        "Authentication removal was not performed because the auth header value did not match the configured pattern.",
                        RequestUtils.requestSnippet(original),
                        baseline.responseSnippet(),
                        "Update or clear the auth header value regex if this request should be tested."
                ));
            }
        }

        HttpRequest modified = RequestUtils.removeHeader(original, config.authHeaderName());
        HttpRequestResponse requestResponse = api.http().sendRequest(modified);
        HttpResponse response = requestResponse.response();
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            return List.of(toFinding(original, modified, baseline, response, "Info", config.authHeaderName(),
                    "Auth removal behaved as expected. Modified request without the auth header returned " + response.statusCode() + "."));
        }

        String body = response.bodyToString();
        double similarity = RequestUtils.similarity(baseline.responseSnippet(), body);
        if ((response.statusCode() == 200 || response.statusCode() == 201 || response.statusCode() == 204) && similarity >= 0.65) {
            findings.add(toFinding(original, modified, baseline, response, "High", config.authHeaderName(),
                    "Unauthenticated response returned " + response.statusCode() + " and looked similar to the authenticated baseline."));
        } else if (RequestUtils.containsSensitiveJsonKey(body)) {
            findings.add(toFinding(original, modified, baseline, response, "Medium", config.authHeaderName(),
                    "Unauthenticated response still contained sensitive-looking JSON keys."));
        } else {
            findings.add(toFinding(original, modified, baseline, response, "Info", config.authHeaderName(),
                    "Auth removal test completed. Modified request without the auth header returned " + response.statusCode() + " without automated sensitive-data indicators."));
        }
        return findings;
    }

    private Finding toFinding(HttpRequest original, HttpRequest modified, Baseline baseline, HttpResponse response, String severity, String authHeaderName, String evidence) {
        return new Finding(
                RequestUtils.endpoint(original),
                original.method(),
                "Authentication Removal",
                severity,
                baseline.statusCode(),
                response.statusCode(),
                "Removed header: " + authHeaderName,
                "(removed auth header)",
                evidence,
                RequestUtils.requestSnippet(modified),
                response.toString(),
                "Require authentication and authorization before returning API data. Return 401 or 403 for unauthenticated requests."
        );
    }
}
