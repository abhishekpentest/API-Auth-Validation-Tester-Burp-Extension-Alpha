package com.example.burp.apiauthvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class BaselineService {
    private final MontoyaApi api;
    private final RequestPreparer requestPreparer;

    public BaselineService(MontoyaApi api) {
        this.api = api;
        this.requestPreparer = RequestPreparer.identity();
    }

    public BaselineService(MontoyaApi api, RequestPreparer requestPreparer) {
        this.api = api;
        this.requestPreparer = requestPreparer;
    }

    public Baseline capture(HttpRequest request) {
        HttpRequest preparedRequest = requestPreparer.prepare(request);
        HttpRequestResponse requestResponse = api.http().sendRequest(preparedRequest);
        HttpResponse response = requestResponse.response();
        return new Baseline(
                response.statusCode(),
                response.body().length(),
                RequestUtils.responseHeaderValue(response, "Content-Type"),
                response.bodyToString().hashCode(),
                response.toString()
        );
    }
}
