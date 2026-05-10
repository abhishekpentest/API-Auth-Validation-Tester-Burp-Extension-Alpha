package com.example.burp.apiauthvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;

public class InputValidationTester {
    public static final List<String> PAYLOADS = List.of(
            "!",
            "\"",
            "#",
            "$",
            "%",
            "&",
            "'",
            "(",
            ")",
            "*",
            "+",
            ",",
            "-",
            ".",
            "/",
            ":",
            ";",
            "<",
            "=",
            ">",
            "?",
            "@",
            "[",
            "\\",
            "]",
            "^",
            "_",
            "`",
            "{",
            "|",
            "}",
            "~"
    );

    private final MontoyaApi api;
    private final RequestPreparer requestPreparer;

    public InputValidationTester(MontoyaApi api) {
        this.api = api;
        this.requestPreparer = RequestPreparer.identity();
    }

    public InputValidationTester(MontoyaApi api, RequestPreparer requestPreparer) {
        this.api = api;
        this.requestPreparer = requestPreparer;
    }

    public List<Finding> test(HttpRequest original, Baseline baseline, ScanConfig config) {
        List<Finding> findings = new ArrayList<>();
        if (config.testQueryParams()) {
            for (ParsedHttpParameter parameter : RequestUtils.queryParameters(original)) {
                for (String payload : PAYLOADS) {
                    findings.addAll(runOne(original, RequestUtils.replaceParameter(original, parameter, payload), baseline, "Query Parameter", parameter.name(), payload));
                }
            }
        }
        if (config.testFormBody() && RequestUtils.looksForm(original)) {
            for (ParsedHttpParameter parameter : RequestUtils.formParameters(original)) {
                for (String payload : PAYLOADS) {
                    findings.addAll(runOne(original, RequestUtils.replaceParameter(original, parameter, payload), baseline, "Form Field", parameter.name(), payload));
                }
            }
        }
        if (config.testJsonBody() && RequestUtils.looksJson(original)) {
            for (String field : RequestUtils.jsonFields(original.bodyToString()).keySet()) {
                for (String payload : PAYLOADS) {
                    findings.addAll(runOne(original, RequestUtils.replaceJsonField(original, field, payload), baseline, "JSON Field", field, payload));
                }
            }
        }
        if (config.testHeaders()) {
            for (String header : RequestUtils.selectedHeaderNames(original, config.authHeaderName())) {
                for (String payload : PAYLOADS) {
                    findings.addAll(runOne(original, RequestUtils.replaceHeader(original, header, payload), baseline, "Header", header, payload));
                }
            }
        }
        return findings;
    }

    private List<Finding> runOne(HttpRequest original, HttpRequest modified, Baseline baseline, String locationType, String name, String payload) {
        HttpRequest preparedModified = requestPreparer.prepare(modified);
        HttpRequestResponse requestResponse = api.http().sendRequest(preparedModified);
        HttpResponse response = requestResponse.response();
        String body = response.bodyToString();
        String evidence;
        String severity;
        if (RequestUtils.responseHasServerError(response)) {
            severity = "Medium";
            evidence = "Server error for special character `" + printable(payload) + "`: modified input caused a " + response.statusCode() + " response.";
        } else if (RequestUtils.containsErrorPattern(body)) {
            severity = "Medium";
            evidence = "Server error pattern for special character `" + printable(payload) + "`: response contained stack trace, SQL, validation, or runtime error indicators.";
        } else if (RequestUtils.reflectsPayload(body, payload) && ("\"'<>`\\|&".contains(payload))) {
            severity = "Medium";
            evidence = "Allowed special character `" + printable(payload) + "` and reflected it in the response. Review contextual output encoding.";
        } else if (response.statusCode() >= 400 && response.statusCode() < 500) {
            severity = "Info";
            evidence = "Rejected special character `" + printable(payload) + "` with HTTP " + response.statusCode() + ".";
        } else if (body.toLowerCase().contains("valid") && RequestUtils.differsMeaningfully(baseline, response)) {
            severity = "Low";
            evidence = "Validation response for special character `" + printable(payload) + "`: response changed meaningfully and contained validation-related language.";
        } else {
            severity = "Info";
            evidence = "Allowed special character `" + printable(payload) + "` with HTTP " + response.statusCode() + " and no automated error indicators.";
        }
        return List.of(new Finding(
                RequestUtils.endpoint(original),
                original.method(),
                "Input Validation",
                severity,
                baseline.statusCode(),
                response.statusCode(),
                locationType + ": " + name,
                payload,
                evidence,
                RequestUtils.requestSnippet(preparedModified),
                response.toString(),
                "Validate input by type, length, format, and allow-list constraints. Handle invalid data with controlled 4xx errors."
        ));
    }

    private String printable(String payload) {
        if ("\\".equals(payload)) {
            return "\\\\";
        }
        if ("`".equals(payload)) {
            return "\\`";
        }
        return payload;
    }
}
