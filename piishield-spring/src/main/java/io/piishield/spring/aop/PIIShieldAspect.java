package io.piishield.spring.aop;

import io.piishield.core.PIIShieldEngine;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

@Aspect
public class PIIShieldAspect {

    private final PIIShieldEngine engine;

    public PIIShieldAspect(PIIShieldEngine engine) {
        this.engine = engine;
    }

    @Around("@annotation(io.piishield.spring.aop.SensitiveData) || @within(io.piishield.spring.aop.SensitiveData)")
    public Object sanitizeReturnValue(ProceedingJoinPoint joinPoint) throws Throwable {
        Object result = joinPoint.proceed();
        if (result instanceof String str) {
            return engine.sanitizeQuick(str);
        }
        return result;
    }
}
