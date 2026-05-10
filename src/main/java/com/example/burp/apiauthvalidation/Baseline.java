package com.example.burp.apiauthvalidation;

public record Baseline(
        short statusCode,
        int responseLength,
        String contentType,
        int bodyHash,
        String responseSnippet
) {
}
