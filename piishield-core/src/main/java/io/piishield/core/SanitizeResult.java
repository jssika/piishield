package io.piishield.core;

import io.piishield.core.audit.AuditEvent;

import java.util.List;

public final class SanitizeResult {

    private final String sanitizedText;
    private final boolean modified;
    private final List<AuditEvent> events;

    public SanitizeResult(String sanitizedText, boolean modified, List<AuditEvent> events) {
        this.sanitizedText = sanitizedText;
        this.modified = modified;
        this.events = List.copyOf(events);
    }

    public String getSanitizedText() { return sanitizedText; }
    public boolean isModified() { return modified; }
    public List<AuditEvent> getEvents() { return events; }
}
