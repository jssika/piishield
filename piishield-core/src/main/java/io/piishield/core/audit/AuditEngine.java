package io.piishield.core.audit;

import io.piishield.core.policy.PolicyAction;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public class AuditEngine {

    private final List<AuditEvent> events = new CopyOnWriteArrayList<>();
    private Consumer<AuditEvent> listener;

    public void record(String detectionType, PolicyAction action, String location, double confidence) {
        AuditEvent event = new AuditEvent(detectionType, action, location, confidence);
        events.add(event);
        if (listener != null) {
            listener.accept(event);
        }
    }

    public List<AuditEvent> getEvents() {
        return Collections.unmodifiableList(events);
    }

    public void clear() {
        events.clear();
    }

    public void setListener(Consumer<AuditEvent> listener) {
        this.listener = listener;
    }
}
