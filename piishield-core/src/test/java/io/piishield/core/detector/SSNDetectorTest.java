package io.piishield.core.detector;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SSNDetectorTest {

    private final SSNDetector detector = new SSNDetector();

    @Test
    void detectsDashedSSN() {
        List<Detection> hits = detector.detect("Customer SSN: 123-45-6789");
        assertThat(hits).hasSize(1);
        assertThat(hits.get(0).getValue()).isEqualTo("123-45-6789");
    }

    @Test
    void detectsUndashedSSN() {
        List<Detection> hits = detector.detect("SSN=123456789");
        assertThat(hits).hasSize(1);
    }

    @Test
    void ignoresAllZeroSegments() {
        assertThat(detector.detect("000-45-6789")).isEmpty();
        assertThat(detector.detect("123-00-6789")).isEmpty();
        assertThat(detector.detect("123-45-0000")).isEmpty();
    }

    @Test
    void ignoresPlainNumbers() {
        assertThat(detector.detect("Order #1234567890")).isEmpty();
    }
}
