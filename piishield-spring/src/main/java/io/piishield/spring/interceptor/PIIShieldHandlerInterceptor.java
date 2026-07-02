package io.piishield.spring.interceptor;

import io.piishield.core.PIIShieldEngine;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

public class PIIShieldHandlerInterceptor implements HandlerInterceptor {

    private final PIIShieldEngine engine;

    public PIIShieldHandlerInterceptor(PIIShieldEngine engine) {
        this.engine = engine;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        // Sanitize any values stored in request attributes set by upstream filters
        request.getAttributeNames().asIterator().forEachRemaining(attr -> {
            Object value = request.getAttribute(attr);
            if (value instanceof String str) {
                String sanitized = engine.sanitizeQuick(str);
                if (!sanitized.equals(str)) {
                    request.setAttribute(attr, sanitized);
                }
            }
        });
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response,
                           Object handler, ModelAndView modelAndView) {
        if (modelAndView != null) {
            modelAndView.getModel().replaceAll((key, value) -> {
                if (value instanceof String str) {
                    return engine.sanitizeQuick(str);
                }
                return value;
            });
        }
    }
}
