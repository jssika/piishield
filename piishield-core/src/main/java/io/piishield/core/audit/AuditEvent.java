package io.piishield.core.audit;

import io.piishield.core.policy.PolicyAction;

import java.time.Instant;

public final class AuditEvent {

    private final String type;
    private final PolicyAction action;
    private final String location;
    private final double confidence;
    private final Instant timestamp;

    public AuditEvent(String type, PolicyAction action, String location, double confidence) {
        this.type = type;
        this.action = action;
        this.location = location;
        this.confidence = confidence;
        this.timestamp = Instant.now();
    }

    public String getType() { return type; }
    public PolicyAction getAction() { return action; }
    public String getLocation() { return location; }
    public double getConfidence() { return confidence; }
    public Instant getTimestamp() { return timestamp; }

    @Override
    public String toString() {
        return "{\"type\":\"" + type + "\",\"action\":\"" + action + "\",\"location\":\"" + location +
               "\",\"confidence\":" + confidence + ",\"timestamp\":\"" + timestamp + "\"}";
    }
}
