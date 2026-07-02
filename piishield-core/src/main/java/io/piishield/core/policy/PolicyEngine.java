package io.piishield.core.policy;

import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.Map;

public class PolicyEngine {

    private final PIIShieldConfig config;

    public PolicyEngine() {
        this(new PIIShieldConfig());
    }

    public PolicyEngine(PIIShieldConfig config) {
        this.config = config;
    }

    public static PolicyEngine fromYaml(InputStream yamlStream) {
        Yaml yaml = new Yaml();
        Map<String, Object> root = yaml.load(yamlStream);
        PIIShieldConfig config = new PIIShieldConfig();

        if (root != null && root.containsKey("piishield")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> piishield = (Map<String, Object>) root.get("piishield");
            if (piishield.containsKey("detectors")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> detectorsMap = (Map<String, Object>) piishield.get("detectors");
                detectorsMap.forEach((key, value) -> {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> detectorCfg = (Map<String, Object>) value;
                    DetectorPolicy policy = new DetectorPolicy();
                    if (detectorCfg.containsKey("enabled")) {
                        policy.setEnabled((Boolean) detectorCfg.get("enabled"));
                    }
                    if (detectorCfg.containsKey("action")) {
                        policy.setAction(PolicyAction.valueOf(((String) detectorCfg.get("action")).toUpperCase()));
                    }
                    config.getDetectors().put(key.toUpperCase(), policy);
                });
            }
        }
        return new PolicyEngine(config);
    }

    public DetectorPolicy policyFor(String detectionType) {
        return config.forType(detectionType);
    }

    public PIIShieldConfig getConfig() {
        return config;
    }
}
