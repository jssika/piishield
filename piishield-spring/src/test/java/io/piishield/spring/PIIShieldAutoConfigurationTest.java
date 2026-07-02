package io.piishield.spring;

import io.piishield.core.PIIShieldEngine;
import io.piishield.spring.config.PIIShieldAutoConfiguration;
import io.piishield.spring.config.PIIShieldProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class PIIShieldAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(PIIShieldAutoConfiguration.class));

    @Test
    void beansAreRegisteredByDefault() {
        contextRunner.run(ctx -> {
            assertThat(ctx).hasSingleBean(PIIShieldEngine.class);
            assertThat(ctx).hasSingleBean(PIIShieldProperties.class);
        });
    }

    @Test
    void engineIsDisabledWhenPropertyFalse() {
        contextRunner
            .withPropertyValues("piishield.enabled=false")
            .run(ctx -> assertThat(ctx).doesNotHaveBean(PIIShieldEngine.class));
    }

    @Test
    void customDetectorPolicyApplied() {
        contextRunner
            .withPropertyValues("piishield.detectors.SSN.action=REMOVE")
            .run(ctx -> {
                PIIShieldEngine engine = ctx.getBean(PIIShieldEngine.class);
                String result = engine.sanitizeQuick("SSN: 123-45-6789");
                assertThat(result).contains("<SSN_REDACTED>");
            });
    }
}
