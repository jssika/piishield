package io.piishield.spring.logback;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.AppenderBase;
import io.piishield.core.PIIShieldEngine;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Wraps all existing Logback appenders on the root logger and sanitizes
 * log messages before they reach any downstream appender.
 *
 * Installed automatically by Spring auto-configuration when piishield.logback.enabled=true.
 * Can also be wired manually in logback-spring.xml as a wrapping appender.
 */
public class PIIShieldLogbackAppender extends AppenderBase<ILoggingEvent> {

    private final PIIShieldEngine engine;
    private final List<Appender<ILoggingEvent>> delegates = new ArrayList<>();

    public PIIShieldLogbackAppender(PIIShieldEngine engine) {
        this.engine = engine;
        setName("PIIShield");
    }

    /**
     * Replaces all appenders on the root logger with this one, storing the
     * originals as delegates so log output is preserved but sanitized.
     */
    public void install() {
        if (!(LoggerFactory.getILoggerFactory() instanceof LoggerContext context)) return;

        Logger root = context.getLogger(Logger.ROOT_LOGGER_NAME);

        Iterator<Appender<ILoggingEvent>> iter = root.iteratorForAppenders();
        while (iter.hasNext()) {
            Appender<ILoggingEvent> existing = iter.next();
            if (!(existing instanceof PIIShieldLogbackAppender)) {
                delegates.add(existing);
            }
        }

        // detachAndStopAllAppenders would stop the delegates, making doAppend() a no-op.
        // Detach each one individually so they stay started and can still forward events.
        for (Appender<ILoggingEvent> delegate : delegates) {
            root.detachAppender(delegate);
        }
        setContext(context);
        start();
        root.addAppender(this);
    }

    @Override
    protected void append(ILoggingEvent event) {
        String sanitized = engine.sanitizeQuick(event.getFormattedMessage());
        ILoggingEvent sanitizedEvent = new SanitizedLoggingEvent(event, sanitized);
        for (Appender<ILoggingEvent> delegate : delegates) {
            delegate.doAppend(sanitizedEvent);
        }
    }
}
