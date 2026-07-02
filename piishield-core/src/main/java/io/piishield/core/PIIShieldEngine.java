package io.piishield.core;

import io.piishield.core.audit.AuditEngine;
import io.piishield.core.detector.*;
import io.piishield.core.policy.PolicyEngine;
import io.piishield.core.redaction.RedactionEngine;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class PIIShieldEngine {

    private final List<Detector> detectors;
    private final PolicyEngine policyEngine;
    private final RedactionEngine redactionEngine;
    private final AuditEngine auditEngine;

    private PIIShieldEngine(Builder builder) {
        this.detectors = List.copyOf(builder.detectors);
        this.policyEngine = builder.policyEngine;
        this.redactionEngine = builder.redactionEngine;
        this.auditEngine = builder.auditEngine;
    }

    public static PIIShieldEngine withDefaults() {
        return new Builder().build();
    }

    public static PIIShieldEngine fromYaml(InputStream yamlStream) {
        return new Builder()
            .policyEngine(PolicyEngine.fromYaml(yamlStream))
            .build();
    }

    public SanitizeResult sanitize(String text) {
        if (text == null) return new SanitizeResult(null, false, List.of());
        auditEngine.clear();

        var allDetections = new ArrayList<io.piishield.core.detector.Detection>();
        for (Detector detector : detectors) {
            var policy = policyEngine.policyFor(detector.getType());
            if (policy.isEnabled()) {
                allDetections.addAll(detector.detect(text));
            }
        }

        String sanitized = redactionEngine.redact(text, allDetections, policyEngine, auditEngine);
        return new SanitizeResult(sanitized, !sanitized.equals(text), auditEngine.getEvents());
    }

    public String sanitizeQuick(String text) {
        return sanitize(text).getSanitizedText();
    }

    public PolicyEngine getPolicyEngine() { return policyEngine; }
    public AuditEngine getAuditEngine() { return auditEngine; }

    public static class Builder {
        private List<Detector> detectors = new ArrayList<>(List.of(
            new SSNDetector(),
            new EmailDetector(),
            new PhoneDetector(),
            new CreditCardDetector(),
            new JWTDetector(),
            new APIKeyDetector()
        ));
        private PolicyEngine policyEngine = new PolicyEngine();
        private RedactionEngine redactionEngine = new RedactionEngine();
        private AuditEngine auditEngine = new AuditEngine();

        public Builder detectors(List<Detector> detectors) { this.detectors = new ArrayList<>(detectors); return this; }
        public Builder addDetector(Detector detector) { this.detectors.add(detector); return this; }
        public Builder policyEngine(PolicyEngine policyEngine) { this.policyEngine = policyEngine; return this; }
        public Builder auditEngine(AuditEngine auditEngine) { this.auditEngine = auditEngine; return this; }

        public PIIShieldEngine build() {
            return new PIIShieldEngine(this);
        }
    }
}
