package com.example.burp.apiauthvalidation;

public record ScanConfig(
        String targetDomain,
        boolean useBurpScope,
        String authHeaderName,
        String authHeaderValuePattern,
        String refreshEndpointPattern,
        String refreshTokenJsonField,
        String authHeaderValueTemplate,
        boolean testAuthRemoval,
        boolean testQueryParams,
        boolean testJsonBody,
        boolean testFormBody,
        boolean testHeaders,
        boolean testLengthValidation,
        boolean testMassAssignment,
        boolean allowUnsafeMethods,
        RequestSourceMode requestSourceMode,
        int maxRequests,
        int delayMs
) {
}
