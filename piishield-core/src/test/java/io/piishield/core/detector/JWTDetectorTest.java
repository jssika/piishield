package io.piishield.core.detector;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JWTDetectorTest {

    private final JWTDetector detector = new JWTDetector();

    private static final String SAMPLE_JWT =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    @Test
    void detectsJWTInAuthorizationHeader() {
        List<Detection> hits = detector.detect("Authorization: Bearer " + SAMPLE_JWT);
        assertThat(hits).hasSize(1);
        assertThat(hits.get(0).getType()).isEqualTo("JWT");
    }

    @Test
    void detectsRawJWT() {
        assertThat(detector.detect(SAMPLE_JWT)).hasSize(1);
    }

    @Test
    void noFalsePositivesOnPlainBase64() {
        assertThat(detector.detect("dGVzdA==")).isEmpty();
    }
}
