package io.piishield.core.policy;

public class DetectorPolicy {

    private boolean enabled = true;
    private PolicyAction action = PolicyAction.MASK;

    public DetectorPolicy() {}

    public DetectorPolicy(boolean enabled, PolicyAction action) {
        this.enabled = enabled;
        this.action = action;
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public PolicyAction getAction() { return action; }
    public void setAction(PolicyAction action) { this.action = action; }
}
