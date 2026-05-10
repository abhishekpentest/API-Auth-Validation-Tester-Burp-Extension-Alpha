package com.example.burp.apiauthvalidation;

public enum RequestSourceMode {
    EXISTING_PROXY_HISTORY("Existing Proxy history only"),
    NEW_TRAFFIC_ONLY("New traffic after Start only"),
    EXISTING_AND_NEW("Existing history and new traffic");

    private final String label;

    RequestSourceMode(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    @Override
    public String toString() {
        return label;
    }
}
