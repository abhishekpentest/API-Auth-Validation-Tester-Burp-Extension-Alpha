package com.example.burp.apiauthvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class MassAssignmentTester {
    private static final Map<String, String> JSON_FIELDS = new LinkedHashMap<>();
    private static final Map<String, String> FORM_FIELDS = new LinkedHashMap<>();

    static {
        JSON_FIELDS.put("test", "\"test\"");
        FORM_FIELDS.put("test", "test");
    }

    private final MontoyaApi api;
    private final RequestPreparer requestPreparer;

    public MassAssignmentTester(MontoyaApi api) {
        this.api = api;
        this.requestPreparer = RequestPreparer.identity();
    }

    public MassAssignmentTester(MontoyaApi api, RequestPreparer requestPreparer) {
        this.api = api;
        this.requestPreparer = requestPreparer;
    }

    public List<Finding> test(HttpRequest original, Baseline baseline) {
        if (RequestUtils.looksJson(original)) {
            return testModified(original, RequestUtils.addJsonFields(original, JSON_FIELDS), baseline, "JSON body");
        }
        if (RequestUtils.looksForm(original)) {
            return testModified(original, RequestUtils.addFormFields(original, FORM_FIELDS), baseline, "Form body");
        }
        return List.of();
    }

    private List<Finding> testModified(HttpRequest original, HttpRequest modified, Baseline baseline, String location) {
        if (modified == original) {
            return List.of();
        }
        HttpRequest preparedModified = requestPreparer.prepare(modified);
        HttpRequestResponse requestResponse = api.http().sendRequest(preparedModified);
        HttpResponse response = requestResponse.response();
        String body = response.bodyToString();
        String lower = body.toLowerCase();
        boolean reflected = lower.contains("\"test\"") || lower.contains("test=test") || lower.contains("test");
        boolean accepted = (response.statusCode() == 200 || response.statusCode() == 201) && RequestUtils.differsMeaningfully(baseline, response);
        if (!reflected && !accepted) {
            return List.of();
        }
        String severity = reflected && accepted ? "Medium" : "Low";
        return List.of(new Finding(
                RequestUtils.endpoint(original),
                original.method(),
                "Mass Assignment",
                severity,
                baseline.statusCode(),
                response.statusCode(),
                location,
                "Injected extra parameter: test=test",
                reflected ? "Injected test parameter or value appeared in the response." : "Response accepted the request and differed meaningfully from baseline. Manual verification required.",
                RequestUtils.requestSnippet(preparedModified),
                response.toString(),
                "Bind only expected server-side fields and ignore unexpected client-controlled parameters unless explicitly supported."
        ));
    }
}
