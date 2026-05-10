package com.example.burp.apiauthvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;

public class LengthValidationTester {
    private static final List<Integer> LENGTHS = List.of(256, 1024, 4096, 10000);
    private final MontoyaApi api;
    private final RequestPreparer requestPreparer;

    public LengthValidationTester(MontoyaApi api) {
        this.api = api;
        this.requestPreparer = RequestPreparer.identity();
    }

    public LengthValidationTester(MontoyaApi api, RequestPreparer requestPreparer) {
        this.api = api;
        this.requestPreparer = requestPreparer;
    }

    public List<Finding> test(HttpRequest original, Baseline baseline, ScanConfig config) {
        List<Finding> findings = new ArrayList<>();
        if (config.testQueryParams()) {
            for (ParsedHttpParameter parameter : RequestUtils.queryParameters(original)) {
                findings.addAll(testLocation(original, baseline, "Query Parameter", parameter.name(), length -> RequestUtils.replaceParameter(original, parameter, "A".repeat(length))));
            }
        }
        if (config.testFormBody() && RequestUtils.looksForm(original)) {
            for (ParsedHttpParameter parameter : RequestUtils.formParameters(original)) {
                findings.addAll(testLocation(original, baseline, "Form Field", parameter.name(), length -> RequestUtils.replaceParameter(original, parameter, "A".repeat(length))));
            }
        }
        if (config.testJsonBody() && RequestUtils.looksJson(original)) {
            for (String field : RequestUtils.jsonFields(original.bodyToString()).keySet()) {
                findings.addAll(testLocation(original, baseline, "JSON Field", field, length -> RequestUtils.replaceJsonField(original, field, "A".repeat(length))));
            }
        }
        if (config.testHeaders()) {
            for (String header : RequestUtils.selectedHeaderNames(original, config.authHeaderName())) {
                findings.addAll(testLocation(original, baseline, "Header", header, length -> RequestUtils.replaceHeader(original, header, "A".repeat(length))));
            }
        }
        return findings;
    }

    private List<Finding> testLocation(HttpRequest original, Baseline baseline, String locationType, String name, RequestFactory factory) {
        List<Finding> findings = new ArrayList<>();
        for (Integer length : LENGTHS) {
            HttpRequest modified = factory.create(length);
            HttpRequest preparedModified = requestPreparer.prepare(modified);
            HttpRequestResponse requestResponse = api.http().sendRequest(preparedModified);
            HttpResponse response = requestResponse.response();
            String body = response.bodyToString();
            if (RequestUtils.responseHasServerError(response) || RequestUtils.containsErrorPattern(body)) {
                findings.add(new Finding(
                        RequestUtils.endpoint(original),
                        original.method(),
                        "Length Validation",
                        response.statusCode() >= 500 ? "Medium" : "Low",
                        baseline.statusCode(),
                        response.statusCode(),
                        locationType + ": " + name,
                        "A repeated " + length + " times",
                        "Long payload triggered an error or unusual server behavior.",
                        RequestUtils.requestSnippet(preparedModified),
                        response.toString(),
                        "Set maximum lengths for all client-controlled fields and return controlled 4xx errors for oversized values."
                ));
            }
        }
        return findings;
    }

    private interface RequestFactory {
        HttpRequest create(int length);
    }
}
