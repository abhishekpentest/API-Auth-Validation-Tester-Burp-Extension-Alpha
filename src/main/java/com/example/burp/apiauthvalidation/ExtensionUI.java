package com.example.burp.apiauthvalidation;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JRadioButton;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class ExtensionUI {
    private final MontoyaApi api;
    private final JPanel root = new JPanel(new BorderLayout(8, 8));
    private final JTextField targetDomain = new JTextField("api.example.com", 24);
    private final JCheckBox useScope = new JCheckBox("Use Burp Suite scope instead of domain text");
    private final JTextField authHeader = new JTextField("Authorization", 24);
    private final JTextField authPattern = new JTextField("", 24);
    private final JTextField refreshEndpointPattern = new JTextField("", 24);
    private final JTextField refreshTokenJsonField = new JTextField("access_token", 24);
    private final JTextField authHeaderValueTemplate = new JTextField("Bearer {token}", 24);
    private final JCheckBox testAuthRemoval = new JCheckBox("Test auth removal", true);
    private final JCheckBox testQueryParams = new JCheckBox("Test query params", true);
    private final JCheckBox testJsonBody = new JCheckBox("Test JSON body", true);
    private final JCheckBox testFormBody = new JCheckBox("Test form body", true);
    private final JCheckBox testHeaders = new JCheckBox("Test headers", false);
    private final JCheckBox testLengthValidation = new JCheckBox("Test length validation", true);
    private final JCheckBox testMassAssignment = new JCheckBox("Test mass assignment", true);
    private final JCheckBox allowUnsafeMethods = new JCheckBox("Allow unsafe methods");
    private final JRadioButton existingHistoryOnly = new JRadioButton(RequestSourceMode.EXISTING_PROXY_HISTORY.label());
    private final JRadioButton newTrafficOnly = new JRadioButton(RequestSourceMode.NEW_TRAFFIC_ONLY.label());
    private final JRadioButton existingAndNew = new JRadioButton(RequestSourceMode.EXISTING_AND_NEW.label(), true);
    private final JSpinner maxRequests = new JSpinner(new SpinnerNumberModel(50, 1, 5000, 1));
    private final JSpinner delayMs = new JSpinner(new SpinnerNumberModel(250, 0, 60000, 50));
    private final JButton start = new JButton("Start Scan");
    private final JButton stop = new JButton("Stop Scan");
    private final JButton export = new JButton("Export Markdown Report");
    private final DefaultTableModel model = new DefaultTableModel(new String[]{"Endpoint", "Method", "Test Type", "Status", "Severity", "Evidence Summary"}, 0);
    private final JTable table = new JTable(model);
    private final JTextArea log = new JTextArea(8, 120);
    private final List<Finding> findings = new ArrayList<>();
    private final Set<String> testedEndpoints = new LinkedHashSet<>();
    private ScanWorker worker;
    private ScanConfig lastConfig;

    public ExtensionUI(MontoyaApi api) {
        this.api = api;
        build();
        wireEvents();
    }

    public JPanel getComponent() {
        return root;
    }

    private void build() {
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 4, 3, 4);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        int row = 0;
        addRow(form, c, row++, "Target domain", targetDomain);
        addFullRow(form, c, row++, useScope);
        addRow(form, c, row++, "Auth header name", authHeader);
        addRow(form, c, row++, "Auth value regex", authPattern);
        addRow(form, c, row++, "Refresh endpoint regex/contains", refreshEndpointPattern);
        addRow(form, c, row++, "Refresh token JSON field", refreshTokenJsonField);
        addRow(form, c, row++, "Auth header value template", authHeaderValueTemplate);
        addFullRow(form, c, row++, testAuthRemoval);
        addFullRow(form, c, row++, testQueryParams);
        addFullRow(form, c, row++, testJsonBody);
        addFullRow(form, c, row++, testFormBody);
        addFullRow(form, c, row++, testHeaders);
        addFullRow(form, c, row++, testLengthValidation);
        addFullRow(form, c, row++, testMassAssignment);
        addFullRow(form, c, row++, allowUnsafeMethods);
        addFullRow(form, c, row++, requestSourcePanel());
        addRow(form, c, row++, "Max requests", maxRequests);
        addRow(form, c, row++, "Delay between requests (ms)", delayMs);

        JPanel buttons = new JPanel();
        buttons.add(start);
        buttons.add(stop);
        buttons.add(export);
        addFullRow(form, c, row, buttons);

        stop.setEnabled(false);
        log.setEditable(false);
        table.setAutoCreateRowSorter(true);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), new JScrollPane(log));
        split.setResizeWeight(0.75);
        root.add(form, BorderLayout.NORTH);
        root.add(split, BorderLayout.CENTER);
    }

    private void wireEvents() {
        start.addActionListener(e -> startScan());
        stop.addActionListener(e -> {
            if (worker != null) {
                worker.cancel(true);
                appendLog("Stop requested.");
            }
        });
        export.addActionListener(e -> exportReport());
    }

    private void startScan() {
        lastConfig = readConfig();
        findings.clear();
        testedEndpoints.clear();
        model.setRowCount(0);
        log.setText("");
        worker = new ScanWorker(lastConfig);
        start.setEnabled(false);
        stop.setEnabled(true);
        worker.execute();
    }

    private ScanConfig readConfig() {
        return new ScanConfig(
                targetDomain.getText().trim(),
                useScope.isSelected(),
                authHeader.getText().trim(),
                authPattern.getText().trim(),
                refreshEndpointPattern.getText().trim(),
                refreshTokenJsonField.getText().trim(),
                authHeaderValueTemplate.getText().trim(),
                testAuthRemoval.isSelected(),
                testQueryParams.isSelected(),
                testJsonBody.isSelected(),
                testFormBody.isSelected(),
                testHeaders.isSelected(),
                testLengthValidation.isSelected(),
                testMassAssignment.isSelected(),
                allowUnsafeMethods.isSelected(),
                selectedRequestSourceMode(),
                (Integer) maxRequests.getValue(),
                (Integer) delayMs.getValue()
        );
    }

    private void exportReport() {
        if (lastConfig == null) {
            lastConfig = readConfig();
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("api-auth-validation-report.md"));
        if (chooser.showSaveDialog(root) != JFileChooser.APPROVE_OPTION) {
            return;
        }
        try {
            new ReportGenerator().write(chooser.getSelectedFile().toPath(), lastConfig, List.copyOf(testedEndpoints), List.copyOf(findings));
            appendLog("Report written to " + chooser.getSelectedFile().getAbsolutePath());
        } catch (Exception ex) {
            appendLog("Failed to write report: " + ex.getMessage());
            api.logging().logToError(ex);
        }
    }

    private void appendFinding(Finding finding) {
        findings.add(finding);
        model.addRow(new Object[]{
                finding.endpoint(),
                finding.method(),
                finding.testType(),
                finding.modifiedStatus(),
                finding.severity(),
                finding.evidenceSummary()
        });
    }

    private void appendLog(String message) {
        SwingUtilities.invokeLater(() -> log.append(message + "\n"));
    }

    private void addRow(JPanel panel, GridBagConstraints c, int row, String label, java.awt.Component component) {
        c.gridy = row;
        c.gridx = 0;
        c.weightx = 0;
        panel.add(new JLabel(label), c);
        c.gridx = 1;
        c.weightx = 1;
        panel.add(component, c);
    }

    private void addFullRow(JPanel panel, GridBagConstraints c, int row, java.awt.Component component) {
        c.gridy = row;
        c.gridx = 0;
        c.gridwidth = 2;
        c.weightx = 1;
        panel.add(component, c);
        c.gridwidth = 1;
    }

    private JPanel requestSourcePanel() {
        ButtonGroup group = new ButtonGroup();
        group.add(existingHistoryOnly);
        group.add(newTrafficOnly);
        group.add(existingAndNew);

        JPanel panel = new JPanel();
        panel.add(new JLabel("Request source:"));
        panel.add(existingHistoryOnly);
        panel.add(newTrafficOnly);
        panel.add(existingAndNew);
        return panel;
    }

    private RequestSourceMode selectedRequestSourceMode() {
        if (existingHistoryOnly.isSelected()) {
            return RequestSourceMode.EXISTING_PROXY_HISTORY;
        }
        if (newTrafficOnly.isSelected()) {
            return RequestSourceMode.NEW_TRAFFIC_ONLY;
        }
        return RequestSourceMode.EXISTING_AND_NEW;
    }

    private class ScanWorker extends SwingWorker<Void, Finding> {
        private final ScanConfig config;
        private final LinkedBlockingQueue<HttpRequest> queue = new LinkedBlockingQueue<>();
        private final Set<String> observedRequestKeys = ConcurrentHashMap.newKeySet();
        private final Set<String> seenRequestKeys = ConcurrentHashMap.newKeySet();
        private volatile String latestAuthHeaderValue;
        private Registration proxyRegistration;
        private int testedCount;

        private ScanWorker(ScanConfig config) {
            this.config = config;
        }

        @Override
        protected Void doInBackground() {
            BaselineService baselineService = new BaselineService(api, this::applyLatestAuthHeader);
            AuthTester authTester = new AuthTester(api);
            InputValidationTester inputTester = new InputValidationTester(api, this::applyLatestAuthHeader);
            LengthValidationTester lengthTester = new LengthValidationTester(api, this::applyLatestAuthHeader);
            MassAssignmentTester massTester = new MassAssignmentTester(api, this::applyLatestAuthHeader);

            initializeRequestSource();
            while (!isCancelled()) {
                if (shouldPollProxyHistory()) {
                    enqueueFromProxyHistory();
                }
                HttpRequest request;
                try {
                    request = queue.poll(500, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                if (request == null) {
                    if (config.requestSourceMode() == RequestSourceMode.EXISTING_PROXY_HISTORY) {
                        appendLog("Existing Proxy history scan complete. No more queued requests.");
                        break;
                    }
                    continue;
                }
                if (testedCount >= config.maxRequests()) {
                    appendLog("Max request limit reached. Stop and restart to scan more.");
                    break;
                }
                testedCount++;
                HttpRequest requestToTest = request;
                appendLog("Testing " + requestToTest.method() + " " + requestToTest.url());
                try {
                    SwingUtilities.invokeLater(() -> testedEndpoints.add(requestToTest.method() + " " + RequestUtils.endpoint(requestToTest)));
                    Baseline baseline = baselineService.capture(requestToTest);
                    delay();
                    if (config.testAuthRemoval()) {
                        runCheck(requestToTest, baseline, "Authentication", () -> authTester.test(requestToTest, baseline, config));
                    }
                    if (config.testQueryParams() || config.testJsonBody() || config.testFormBody() || config.testHeaders()) {
                        runCheck(requestToTest, baseline, "Input Validation", () -> inputTester.test(requestToTest, baseline, config));
                    }
                    if (config.testLengthValidation()) {
                        runCheck(requestToTest, baseline, "Length Validation", () -> lengthTester.test(requestToTest, baseline, config));
                    }
                    if (config.testMassAssignment()) {
                        runCheck(requestToTest, baseline, "Extra Parameter Check", () -> massTester.test(requestToTest, baseline));
                    }
                    appendLog("Finished " + requestToTest.method() + " " + requestToTest.url());
                } catch (CancellationException e) {
                    break;
                } catch (Exception e) {
                    appendLog("Error testing request: " + e.getMessage());
                    api.logging().logToError(e);
                }
            }
            return null;
        }

        private void initializeRequestSource() {
            switch (config.requestSourceMode()) {
                case EXISTING_PROXY_HISTORY -> {
                    appendLog("Request source: existing Proxy history only.");
                    enqueueFromProxyHistory();
                }
                case NEW_TRAFFIC_ONLY -> {
                    appendLog("Request source: new traffic after Start only.");
                    proxyRegistration = api.proxy().registerResponseHandler(new LiveProxyResponseHandler());
                    appendLog("Live capture started. Existing Proxy history will be ignored, but repeated APIs hit after Start will be tested.");
                }
                case EXISTING_AND_NEW -> {
                    appendLog("Request source: existing Proxy history and new traffic.");
                    enqueueFromProxyHistory();
                    proxyRegistration = api.proxy().registerResponseHandler(new LiveProxyResponseHandler());
                    appendLog("Live capture started. Crawl the application through Burp.");
                }
            }
        }

        private boolean shouldPollProxyHistory() {
            return config.requestSourceMode() == RequestSourceMode.EXISTING_AND_NEW;
        }

        private void enqueueFromProxyHistory() {
            for (ProxyHttpRequestResponse entry : api.proxy().history()) {
                enqueueIfCandidate(entry.finalRequest(), "Proxy history");
            }
        }

        private void enqueueIfCandidate(HttpRequest request, String source) {
            if (request == null || isCancelled()) {
                return;
            }
            if (!shouldTestObservedRequest(request, source)) {
                return;
            }
            if (!RequestUtils.isInScope(api, request, config)) {
                appendLog(source + ": skipped out-of-scope request " + request.method() + " " + request.url());
                return;
            }
            if (!RequestUtils.isApiLike(request)) {
                appendLog(source + ": skipped non API-like request " + request.method() + " " + request.url());
                return;
            }
            if (!RequestUtils.isSafeForActiveTesting(request, config)) {
                appendLog(source + ": skipped unsafe method " + request.method() + " " + request.url());
                return;
            }
            if (RequestUtils.isRefreshEndpoint(request, config)) {
                appendLog(source + ": skipped configured token refresh endpoint from active testing " + request.method() + " " + request.url());
                return;
            }
            if (shouldQueueUniqueApi(request, source)) {
                queue.offer(request);
                appendLog(source + ": captured API for testing: " + request.method() + " " + request.url());
            }
        }

        private boolean shouldTestObservedRequest(HttpRequest request, String source) {
            if (config.requestSourceMode() == RequestSourceMode.NEW_TRAFFIC_ONLY && "Live proxy".equals(source)) {
                return true;
            }
            return observedRequestKeys.add(observedKey(request));
        }

        private boolean shouldQueueUniqueApi(HttpRequest request, String source) {
            if (config.requestSourceMode() == RequestSourceMode.NEW_TRAFFIC_ONLY && "Live proxy".equals(source)) {
                return true;
            }
            return seenRequestKeys.add(RequestUtils.dedupeKey(request));
        }

        private String observedKey(HttpRequest request) {
            return request.method() + " " + request.url() + " " + RequestUtils.sha256(request.bodyToString());
        }

        private HttpRequest applyLatestAuthHeader(HttpRequest request) {
            if (latestAuthHeaderValue == null || latestAuthHeaderValue.isBlank() || config.authHeaderName().isBlank()) {
                return request;
            }
            appendLog("Applying latest live token to " + request.method() + " " + request.url());
            return RequestUtils.replaceHeader(request, config.authHeaderName(), latestAuthHeaderValue);
        }

        private void updateLatestTokenFromRefreshResponse(InterceptedResponse interceptedResponse) {
            HttpRequest request = interceptedResponse.initiatingRequest();
            if (!RequestUtils.isRefreshEndpoint(request, config)) {
                return;
            }
            RequestUtils.extractJsonStringField(interceptedResponse.bodyToString(), config.refreshTokenJsonField())
                    .ifPresentOrElse(token -> {
                        String template = config.authHeaderValueTemplate().isBlank() ? "{token}" : config.authHeaderValueTemplate();
                        latestAuthHeaderValue = template.replace("{token}", token);
                        appendLog("Updated live auth header from refresh endpoint: " + config.authHeaderName() + ": " + maskAuthHeaderValue(latestAuthHeaderValue));
                    }, () -> appendLog("Refresh endpoint matched, but token field was not found: " + config.refreshTokenJsonField()));
        }

        private String maskAuthHeaderValue(String value) {
            if (value == null || value.length() <= 16) {
                return "(set)";
            }
            return value.substring(0, 10) + "..." + value.substring(value.length() - 6);
        }

        private void runCheck(HttpRequest request, Baseline baseline, String checkName, CheckRunner runner) throws InterruptedException {
            appendLog("Starting " + checkName + " for " + request.method() + " " + request.url());
            List<Finding> newFindings = runner.run();
            if (newFindings.isEmpty()) {
                Finding completed = completedFinding(request, baseline, checkName);
                publish(completed);
                appendLog("Completed " + checkName + " with no detailed results.");
                delay();
                return;
            }
            runFindings(newFindings);
            appendLog("Completed " + checkName + " with " + newFindings.size() + " recorded result(s).");
        }

        private Finding completedFinding(HttpRequest request, Baseline baseline, String checkName) {
            String recommendation = switch (checkName) {
                case "Authentication" -> "No automated authentication issue was detected. Manually verify authorization logic for user and tenant boundaries.";
                case "Input Validation", "Length Validation" -> "No automated input validation issue was detected. Manually verify business rules and context-specific encoding.";
                case "Extra Parameter Check" -> "No automated mass-assignment issue was detected. Manually verify server-side binding ignores privileged fields.";
                default -> "No automated issue was detected. Manual verification is still recommended.";
            };
            return new Finding(
                    RequestUtils.endpoint(request),
                    request.method(),
                    checkName,
                    "Info",
                    baseline.statusCode(),
                    baseline.statusCode(),
                    "Whole request",
                    "(baseline / no suspicious payload accepted)",
                    "Test completed. No suspicious behavior was detected by automated heuristic checks.",
                    RequestUtils.requestSnippet(applyLatestAuthHeader(request)),
                    baseline.responseSnippet(),
                    recommendation
            );
        }

        private void runFindings(List<Finding> newFindings) throws InterruptedException {
            for (Finding finding : newFindings) {
                if (isCancelled()) {
                    throw new CancellationException();
                }
                publish(finding);
                delay();
            }
        }

        private void delay() throws InterruptedException {
            if (config.delayMs() > 0) {
                Thread.sleep(config.delayMs());
            }
        }

        @Override
        protected void process(List<Finding> chunks) {
            chunks.forEach(ExtensionUI.this::appendFinding);
        }

        @Override
        protected void done() {
            if (proxyRegistration != null && proxyRegistration.isRegistered()) {
                proxyRegistration.deregister();
            }
            start.setEnabled(true);
            stop.setEnabled(false);
            appendLog(isCancelled() ? "Scan stopped." : "Scan complete.");
        }

        private class LiveProxyResponseHandler implements ProxyResponseHandler {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
                updateLatestTokenFromRefreshResponse(interceptedResponse);
                enqueueIfCandidate(interceptedResponse.initiatingRequest(), "Live proxy");
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }

            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
                return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
            }

        }

        private interface CheckRunner {
            List<Finding> run();
        }
    }
}
