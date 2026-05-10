package com.example.burp.apiauthvalidation;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class ApiAuthValidationTesterExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("API Auth & Validation Tester");
        ExtensionUI ui = new ExtensionUI(api);
        api.userInterface().registerSuiteTab("API Auth & Validation Tester", ui.getComponent());
        api.logging().logToOutput("API Auth & Validation Tester loaded.");
    }
}
