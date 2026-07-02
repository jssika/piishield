package io.piishield.core.policy;

import java.util.HashMap;
import java.util.Map;

public class PIIShieldConfig {

    private Map<String, DetectorPolicy> detectors = new HashMap<>();

    public PIIShieldConfig() {
        // sensible defaults
        detectors.put("SSN",         new DetectorPolicy(true, PolicyAction.MASK));
        detectors.put("EMAIL",       new DetectorPolicy(true, PolicyAction.PARTIAL));
        detectors.put("PHONE",       new DetectorPolicy(true, PolicyAction.MASK));
        detectors.put("CREDIT_CARD", new DetectorPolicy(true, PolicyAction.MASK));
        detectors.put("JWT",         new DetectorPolicy(true, PolicyAction.REMOVE));
        detectors.put("API_KEY",     new DetectorPolicy(true, PolicyAction.REMOVE));
    }

    public Map<String, DetectorPolicy> getDetectors() { return detectors; }
    public void setDetectors(Map<String, DetectorPolicy> detectors) { this.detectors = detectors; }

    public DetectorPolicy forType(String type) {
        // API_KEY subtypes like API_KEY/AWS_ACCESS_KEY fall back to API_KEY policy
        if (detectors.containsKey(type)) return detectors.get(type);
        if (type.contains("/")) {
            String base = type.substring(0, type.indexOf('/'));
            if (detectors.containsKey(base)) return detectors.get(base);
        }
        return new DetectorPolicy(true, PolicyAction.MASK);
    }
}
