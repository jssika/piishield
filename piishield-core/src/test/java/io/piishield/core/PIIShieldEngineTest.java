package io.piishield.core;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PIIShieldEngineTest {

    private final PIIShieldEngine engine = PIIShieldEngine.withDefaults();

    @Test
    void masksSSN() {
        String result = engine.sanitizeQuick("Customer SSN: 123-45-6789");
        assertThat(result).contains("***-**-6789");
        assertThat(result).doesNotContain("123-45-6789");
    }

    @Test
    void partialsEmail() {
        String result = engine.sanitizeQuick("Email: john@gmail.com");
        assertThat(result).contains("j***@gmail.com");
    }

    @Test
    void removesJWT() {
        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
                     ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" +
                     ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String result = engine.sanitizeQuick("Authorization: Bearer " + jwt);
        assertThat(result).contains("<JWT_REDACTED>");
        assertThat(result).doesNotContain("eyJ");
    }

    @Test
    void sanitizeResultTracksModification() {
        SanitizeResult result = engine.sanitize("No PII here");
        assertThat(result.isModified()).isFalse();
        assertThat(result.getEvents()).isEmpty();
    }

    @Test
    void auditEventsRecorded() {
        SanitizeResult result = engine.sanitize("SSN: 123-45-6789 email: a@b.com");
        assertThat(result.isModified()).isTrue();
        assertThat(result.getEvents()).hasSizeGreaterThanOrEqualTo(2);
    }

    @Test
    void handlesNullInput() {
        assertThat(engine.sanitizeQuick(null)).isNull();
    }

    @Test
    void handlesEmptyInput() {
        assertThat(engine.sanitizeQuick("")).isEmpty();
    }

    @Test
    void masksMultiplePIITypes() {
        String input = "Name: John, SSN: 123-45-6789, Card: 4532015112830366, Email: john@example.com";
        String result = engine.sanitizeQuick(input);
        assertThat(result).doesNotContain("123-45-6789");
        assertThat(result).doesNotContain("4532015112830366");
        assertThat(result).doesNotContain("john@example.com");
    }
}
