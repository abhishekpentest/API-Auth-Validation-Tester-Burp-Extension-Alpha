package com.example.burp.apiauthvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.sitemap.SiteMapFilter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class RequestCollector {
    private final MontoyaApi api;

    public RequestCollector(MontoyaApi api) {
        this.api = api;
    }

    public List<HttpRequest> collect(ScanConfig config, Consumer<String> skipLogger) {
        Map<String, HttpRequest> requests = new LinkedHashMap<>();
        for (ProxyHttpRequestResponse entry : api.proxy().history()) {
            addCandidate(entry.finalRequest(), config, requests, skipLogger, "Proxy history");
        }

        SiteMapFilter filter = item -> RequestUtils.isInScope(api, item.requestResponse().request(), config);
        api.siteMap().requestResponses(filter).forEach(item -> addCandidate(item.request(), config, requests, skipLogger, "Site Map"));

        return new ArrayList<>(requests.values()).stream()
                .limit(config.maxRequests())
                .toList();
    }

    private void addCandidate(HttpRequest request, ScanConfig config, Map<String, HttpRequest> requests, Consumer<String> skipLogger, String source) {
        if (request == null) {
            return;
        }
        if (!RequestUtils.isInScope(api, request, config)) {
            skipLogger.accept(source + ": skipped out-of-scope request " + request.method() + " " + request.url());
            return;
        }
        if (!RequestUtils.isApiLike(request)) {
            skipLogger.accept(source + ": skipped non API-like request " + request.method() + " " + request.url());
            return;
        }
        if (!RequestUtils.isSafeForActiveTesting(request, config)) {
            skipLogger.accept(source + ": skipped unsafe method " + request.method() + " " + request.url());
            return;
        }
        requests.putIfAbsent(RequestUtils.dedupeKey(request), request);
    }
}
