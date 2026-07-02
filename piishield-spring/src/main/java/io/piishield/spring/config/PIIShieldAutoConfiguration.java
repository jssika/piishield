package io.piishield.spring.config;

import io.piishield.core.PIIShieldEngine;
import io.piishield.core.policy.DetectorPolicy;
import io.piishield.core.policy.PIIShieldConfig;
import io.piishield.core.policy.PolicyEngine;
import io.piishield.spring.aop.PIIShieldAspect;
import io.piishield.spring.filter.PIIShieldFilter;
import io.piishield.spring.logback.PIIShieldLogbackAppender;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

import java.util.HashMap;
import java.util.Map;

@AutoConfiguration
@EnableConfigurationProperties(PIIShieldProperties.class)
@ConditionalOnProperty(name = "piishield.enabled", havingValue = "true", matchIfMissing = true)
public class PIIShieldAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PolicyEngine piishieldPolicyEngine(PIIShieldProperties properties) {
        PIIShieldConfig config = new PIIShieldConfig();
        Map<String, DetectorPolicy> policies = new HashMap<>();
        properties.getDetectors().forEach((type, dp) ->
            policies.put(type.toUpperCase(), new DetectorPolicy(dp.isEnabled(), dp.getAction()))
        );
        config.setDetectors(policies);
        return new PolicyEngine(config);
    }

    @Bean
    @ConditionalOnMissingBean
    public PIIShieldEngine piishieldEngine(PolicyEngine policyEngine) {
        return new PIIShieldEngine.Builder()
            .policyEngine(policyEngine)
            .build();
    }

    @Bean
    @ConditionalOnWebApplication
    @ConditionalOnProperty(name = "piishield.filter.enabled", havingValue = "true", matchIfMissing = true)
    public FilterRegistrationBean<PIIShieldFilter> piishieldFilter(PIIShieldEngine engine,
                                                                    PIIShieldProperties properties) {
        FilterRegistrationBean<PIIShieldFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new PIIShieldFilter(engine, properties.getFilter()));
        registration.addUrlPatterns("/*");
        registration.setOrder(Integer.MIN_VALUE);
        return registration;
    }

    @Bean
    @ConditionalOnProperty(name = "piishield.aop.enabled", havingValue = "true", matchIfMissing = true)
    public PIIShieldAspect piishieldAspect(PIIShieldEngine engine) {
        return new PIIShieldAspect(engine);
    }

    @Bean
    @ConditionalOnProperty(name = "piishield.logback.enabled", havingValue = "true", matchIfMissing = true)
    public PIIShieldLogbackAppender piishieldLogbackAppender(PIIShieldEngine engine) {
        PIIShieldLogbackAppender appender = new PIIShieldLogbackAppender(engine);
        appender.install();
        return appender;
    }
}
