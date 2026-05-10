package com.example.burp.apiauthvalidation;

public record Finding(
        String endpoint,
        String method,
        String testType,
        String severity,
        short originalStatus,
        short modifiedStatus,
        String location,
        String payload,
        String evidenceSummary,
        String requestSnippet,
        String responseSnippet,
        String recommendation
) {
}
