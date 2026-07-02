package io.piishield.spring.config;

import io.piishield.core.policy.PolicyAction;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "piishield")
public class PIIShieldProperties {

    private boolean enabled = true;
    private Map<String, DetectorProperties> detectors = defaultDetectors();
    private FilterProperties filter = new FilterProperties();
    private LogbackProperties logback = new LogbackProperties();
    private AopProperties aop = new AopProperties();

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Map<String, DetectorProperties> getDetectors() { return detectors; }
    public void setDetectors(Map<String, DetectorProperties> detectors) { this.detectors = detectors; }
    public FilterProperties getFilter() { return filter; }
    public void setFilter(FilterProperties filter) { this.filter = filter; }
    public LogbackProperties getLogback() { return logback; }
    public void setLogback(LogbackProperties logback) { this.logback = logback; }
    public AopProperties getAop() { return aop; }
    public void setAop(AopProperties aop) { this.aop = aop; }

    private static Map<String, DetectorProperties> defaultDetectors() {
        Map<String, DetectorProperties> map = new HashMap<>();
        map.put("SSN",         new DetectorProperties(true, PolicyAction.MASK));
        map.put("EMAIL",       new DetectorProperties(true, PolicyAction.PARTIAL));
        map.put("PHONE",       new DetectorProperties(true, PolicyAction.MASK));
        map.put("CREDIT_CARD", new DetectorProperties(true, PolicyAction.MASK));
        map.put("JWT",         new DetectorProperties(true, PolicyAction.REMOVE));
        map.put("API_KEY",     new DetectorProperties(true, PolicyAction.REMOVE));
        return map;
    }

    public static class DetectorProperties {
        private boolean enabled = true;
        private PolicyAction action = PolicyAction.MASK;

        public DetectorProperties() {}
        public DetectorProperties(boolean enabled, PolicyAction action) {
            this.enabled = enabled;
            this.action = action;
        }

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public PolicyAction getAction() { return action; }
        public void setAction(PolicyAction action) { this.action = action; }
    }

    public static class FilterProperties {
        private boolean enabled = true;
        private boolean sanitizeRequestBody = true;
        private boolean sanitizeResponseBody = true;
        private boolean sanitizeHeaders = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isSanitizeRequestBody() { return sanitizeRequestBody; }
        public void setSanitizeRequestBody(boolean v) { this.sanitizeRequestBody = v; }
        public boolean isSanitizeResponseBody() { return sanitizeResponseBody; }
        public void setSanitizeResponseBody(boolean v) { this.sanitizeResponseBody = v; }
        public boolean isSanitizeHeaders() { return sanitizeHeaders; }
        public void setSanitizeHeaders(boolean v) { this.sanitizeHeaders = v; }
    }

    public static class LogbackProperties {
        private boolean enabled = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class AopProperties {
        private boolean enabled = true;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }
}
