package io.piishield.spring.filter;

import io.piishield.core.PIIShieldEngine;
import io.piishield.spring.config.PIIShieldProperties;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;

public class PIIShieldFilter implements Filter {

    private final PIIShieldEngine engine;
    private final PIIShieldProperties.FilterProperties config;

    public PIIShieldFilter(PIIShieldEngine engine, PIIShieldProperties.FilterProperties config) {
        this.engine = engine;
        this.config = config;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(httpRequest);
        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper((HttpServletResponse) response);

        if (config.isSanitizeHeaders()) {
            sanitizeRequestHeaders(wrappedRequest);
        }

        chain.doFilter(wrappedRequest, wrappedResponse);

        if (config.isSanitizeResponseBody()) {
            byte[] responseBody = wrappedResponse.getContentAsByteArray();
            if (responseBody.length > 0) {
                String original = new String(responseBody, StandardCharsets.UTF_8);
                String sanitized = engine.sanitizeQuick(original);
                wrappedResponse.resetBuffer();
                wrappedResponse.getOutputStream().write(sanitized.getBytes(StandardCharsets.UTF_8));
            }
        }

        wrappedResponse.copyBodyToResponse();
    }

    private void sanitizeRequestHeaders(HttpServletRequest request) {
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                // Authorization and Cookie headers are the main JWT/token carriers — log them sanitized
                if ("authorization".equalsIgnoreCase(name) || "cookie".equalsIgnoreCase(name)) {
                    String value = request.getHeader(name);
                    // The filter cannot modify HttpServletRequest headers, but sanitized values are
                    // available via attributes for logging interceptors that check them
                    if (value != null) {
                        request.setAttribute("piishield.sanitized." + name, engine.sanitizeQuick(value));
                    }
                }
            }
        }
    }
}
