package io.piishield.core.detector;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class EmailDetectorTest {

    private final EmailDetector detector = new EmailDetector();

    @Test
    void detectsSimpleEmail() {
        List<Detection> hits = detector.detect("Contact john@example.com for help");
        assertThat(hits).hasSize(1);
        assertThat(hits.get(0).getValue()).isEqualTo("john@example.com");
    }

    @Test
    void detectsMultipleEmails() {
        List<Detection> hits = detector.detect("From: a@b.com To: c@d.org");
        assertThat(hits).hasSize(2);
    }

    @Test
    void detectsPlusAddressedEmail() {
        assertThat(detector.detect("user+tag@company.co.uk")).hasSize(1);
    }

    @Test
    void noFalsePositivesOnPlainText() {
        assertThat(detector.detect("No emails here")).isEmpty();
    }
}
