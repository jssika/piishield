package io.piishield.core.detector;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CreditCardDetectorTest {

    private final CreditCardDetector detector = new CreditCardDetector();

    @Test
    void detectsVisaCard() {
        // Valid Luhn number
        List<Detection> hits = detector.detect("Card: 4532015112830366");
        assertThat(hits).hasSize(1);
    }

    @Test
    void detectsCardWithDashes() {
        List<Detection> hits = detector.detect("4532-0151-1283-0366");
        assertThat(hits).hasSize(1);
    }

    @Test
    void detectsCardWithSpaces() {
        List<Detection> hits = detector.detect("4532 0151 1283 0366");
        assertThat(hits).hasSize(1);
    }

    @Test
    void rejectsInvalidLuhn() {
        // Invalid checksum
        assertThat(detector.detect("4532015112830360")).isEmpty();
    }

    @Test
    void detectsMastercardNumber() {
        List<Detection> hits = detector.detect("5500005555555559");
        assertThat(hits).hasSize(1);
    }
}
