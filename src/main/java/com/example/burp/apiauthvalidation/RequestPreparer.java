package com.example.burp.apiauthvalidation;

import burp.api.montoya.http.message.requests.HttpRequest;

@FunctionalInterface
public interface RequestPreparer {
    HttpRequest prepare(HttpRequest request);

    static RequestPreparer identity() {
        return request -> request;
    }
}
