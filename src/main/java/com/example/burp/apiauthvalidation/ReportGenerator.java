package com.example.burp.apiauthvalidation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ReportGenerator {
    public void write(Path path, ScanConfig config, List<Finding> findings) throws IOException {
        write(path, config, List.of(), findings);
    }

    public void write(Path path, ScanConfig config, List<String> testedEndpoints, List<Finding> findings) throws IOException {
        Files.writeString(path, render(config, testedEndpoints, findings), StandardCharsets.UTF_8);
    }

    private String render(ScanConfig config, List<String> testedEndpoints, List<Finding> findings) {
        StringBuilder md = new StringBuilder();
        md.append("# API Auth & Validation Tester Report\n\n");
        md.append("- Date/time: ").append(ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)).append("\n");
        md.append("- Scope/domain: ").append(config.useBurpScope() ? "Burp Suite scope" : escape(config.targetDomain())).append("\n");
        md.append("- Request source mode: ").append(escape(config.requestSourceMode().label())).append("\n");
        md.append("- Refresh endpoint tracking: ").append(config.refreshEndpointPattern().isBlank() ? "disabled" : "enabled").append("\n");
        if (!config.refreshEndpointPattern().isBlank()) {
            md.append("- Refresh endpoint pattern: `").append(escape(config.refreshEndpointPattern())).append("`\n");
            md.append("- Refresh token JSON field: `").append(escape(config.refreshTokenJsonField())).append("`\n");
            md.append("- Auth header value template: `").append(escape(config.authHeaderValueTemplate())).append("`\n");
        }
        md.append("- Endpoints tested: ").append(testedEndpoints.size()).append("\n");
        md.append("- Recorded results: ").append(findings.size()).append("\n\n");

        md.append("## Endpoints Tested\n\n");
        if (testedEndpoints.isEmpty()) {
            md.append("_No endpoints were tested._\n\n");
        } else {
            for (String endpoint : testedEndpoints) {
                md.append("- `").append(escape(endpoint)).append("`\n");
            }
            md.append("\n");
        }

        md.append("## Summary\n\n");
        md.append("| Severity | Count |\n|---|---:|\n");
        for (String severity : List.of("High", "Medium", "Low", "Info")) {
            long count = findings.stream().filter(f -> f.severity().equalsIgnoreCase(severity)).count();
            md.append("| ").append(severity).append(" | ").append(count).append(" |\n");
        }
        md.append("\n");

        appendEndpointFindings(md, testedEndpoints, findings);
        return md.toString();
    }

    private void appendEndpointFindings(StringBuilder md, List<String> testedEndpoints, List<Finding> findings) {
        Map<String, List<Finding>> byEndpoint = findings.stream()
                .collect(Collectors.groupingBy(f -> f.method() + " " + f.endpoint(), LinkedHashMap::new, Collectors.toList()));
        for (String endpoint : testedEndpoints) {
            md.append("## ").append(escape(endpoint)).append("\n\n");
            appendSection(md, "Authentication", byEndpoint.getOrDefault(endpoint, List.of()), "Authentication", "Authentication Removal");
            appendSection(md, "Input Validation", byEndpoint.getOrDefault(endpoint, List.of()), "Input Validation", "Length Validation");
            appendSection(md, "Extra Parameter Check", byEndpoint.getOrDefault(endpoint, List.of()), "Extra Parameter Check", "Mass Assignment");
        }
        for (Map.Entry<String, List<Finding>> entry : byEndpoint.entrySet()) {
            if (!testedEndpoints.contains(entry.getKey())) {
                md.append("## ").append(escape(entry.getKey())).append("\n\n");
                appendSection(md, "Authentication", entry.getValue(), "Authentication", "Authentication Removal");
                appendSection(md, "Input Validation", entry.getValue(), "Input Validation", "Length Validation");
                appendSection(md, "Extra Parameter Check", entry.getValue(), "Extra Parameter Check", "Mass Assignment");
            }
        }
    }

    private void appendSection(StringBuilder md, String title, List<Finding> endpointFindings, String... testTypes) {
        md.append("### ").append(title).append("\n\n");
        List<String> wantedTypes = List.of(testTypes);
        List<Finding> sectionFindings = endpointFindings.stream()
                .filter(f -> wantedTypes.contains(f.testType()))
                .sorted(Comparator.comparing(Finding::severity))
                .toList();
        if (sectionFindings.isEmpty()) {
            md.append("_This check was not run or no evidence was recorded._\n\n");
            return;
        }
        if ("Input Validation".equals(title)) {
            appendInputValidationMatrix(md, sectionFindings);
        }
        for (Finding finding : sectionFindings) {
            appendFinding(md, finding);
        }
    }

    private void appendInputValidationMatrix(StringBuilder md, List<Finding> sectionFindings) {
        List<Finding> inputFindings = sectionFindings.stream()
                .filter(f -> "Input Validation".equals(f.testType()))
                .toList();
        if (inputFindings.isEmpty()) {
            return;
        }

        Map<String, List<Finding>> byLocation = inputFindings.stream()
                .collect(Collectors.groupingBy(Finding::location, LinkedHashMap::new, Collectors.toList()));

        md.append("#### Special Character Allowance Matrix\n\n");
        md.append("| Parameter / Field | Allowed special characters | Rejected / errored special characters | Suspicious accepted characters |\n");
        md.append("|---|---|---|---|\n");
        for (Map.Entry<String, List<Finding>> entry : byLocation.entrySet()) {
            String allowed = entry.getValue().stream()
                    .filter(this::isAllowedSpecialCharacter)
                    .map(f -> displayPayload(f.payload()))
                    .distinct()
                    .collect(Collectors.joining(" "));
            String rejected = entry.getValue().stream()
                    .filter(this::isRejectedOrErroredSpecialCharacter)
                    .map(f -> displayPayload(f.payload()))
                    .distinct()
                    .collect(Collectors.joining(" "));
            String suspicious = entry.getValue().stream()
                    .filter(f -> isAllowedSpecialCharacter(f) && !"Info".equalsIgnoreCase(f.severity()))
                    .map(f -> displayPayload(f.payload()))
                    .distinct()
                    .collect(Collectors.joining(" "));
            md.append("| ")
                    .append(escape(entry.getKey()))
                    .append(" | ")
                    .append(allowed.isBlank() ? "-" : allowed)
                    .append(" | ")
                    .append(rejected.isBlank() ? "-" : rejected)
                    .append(" | ")
                    .append(suspicious.isBlank() ? "-" : suspicious)
                    .append(" |\n");
        }
        md.append("\n");
    }

    private boolean isAllowedSpecialCharacter(Finding finding) {
        return finding.evidenceSummary().startsWith("Allowed special character");
    }

    private boolean isRejectedOrErroredSpecialCharacter(Finding finding) {
        return finding.evidenceSummary().startsWith("Rejected special character")
                || finding.evidenceSummary().startsWith("Server error")
                || finding.evidenceSummary().startsWith("Validation response");
    }

    private String displayPayload(String payload) {
        return "`" + escape(payload)
                .replace("\\", "\\\\")
                .replace("`", "\\`")
                .replace("\n", "\\n")
                + "`";
    }

    private void appendFinding(StringBuilder md, Finding f) {
        md.append("#### ").append(escape(f.severity())).append(": ").append(escape(f.testType())).append("\n\n");
        md.append("| Field | Value |\n|---|---|\n");
        md.append("| Test type | ").append(escape(f.testType())).append(" |\n");
        md.append("| Severity | ").append(escape(f.severity())).append(" |\n");
        md.append("| Original status | ").append(f.originalStatus()).append(" |\n");
        md.append("| Modified status | ").append(f.modifiedStatus()).append(" |\n");
        md.append("| Modified location | ").append(escape(f.location())).append(" |\n");
        md.append("| Payload used | `").append(escape(f.payload())).append("` |\n\n");
        md.append("**Evidence summary:** ").append(escape(f.evidenceSummary())).append("\n\n");
        md.append("**Request snippet**\n\n```http\n").append(f.requestSnippet()).append("\n```\n\n");
        md.append("**Response snippet**\n\n```text\n").append(f.responseSnippet()).append("\n```\n\n");
        md.append("**Recommendation:** ").append(escape(f.recommendation())).append("\n\n");
    }

    private String escape(String value) {
        return value == null ? "" : value.replace("|", "\\|");
    }
}
