package io.piishield.spring.aop;

import java.lang.annotation.*;

/**
 * Marks a method whose String return value should be sanitized by PIIShield before being returned.
 * Place on service or repository methods that may return raw PII.
 *
 * <pre>{@code
 * @SensitiveData
 * public String getCustomerDetails(long id) { ... }
 * }</pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface SensitiveData {
}
