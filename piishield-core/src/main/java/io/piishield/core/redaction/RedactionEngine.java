package io.piishield.core.redaction;

import io.piishield.core.audit.AuditEngine;
import io.piishield.core.detector.Detection;
import io.piishield.core.policy.DetectorPolicy;
import io.piishield.core.policy.PolicyAction;
import io.piishield.core.policy.PolicyEngine;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RedactionEngine {

    private final Map<String, String> tokenStore = new ConcurrentHashMap<>();

    public String redact(String text, List<Detection> detections, PolicyEngine policyEngine, AuditEngine auditEngine) {
        if (text == null || detections.isEmpty()) return text;

        // Sort descending by start so replacements don't shift subsequent indices
        List<Detection> sorted = detections.stream()
            .sorted(Comparator.comparingInt(Detection::getStart).reversed())
            .toList();

        StringBuilder result = new StringBuilder(text);
        int lastStart = Integer.MAX_VALUE;

        for (Detection detection : sorted) {
            // Skip detections that overlap with an already-processed one
            if (detection.getEnd() > lastStart) continue;

            DetectorPolicy policy = policyEngine.policyFor(detection.getType());
            if (!policy.isEnabled() || policy.getAction() == PolicyAction.ALLOW) continue;

            String replacement = applyAction(detection, policy.getAction());
            result.replace(detection.getStart(), detection.getEnd(), replacement);
            lastStart = detection.getStart();

            if (auditEngine != null) {
                auditEngine.record(detection.getType(), policy.getAction(), "text", detection.getConfidence());
            }
        }

        return result.toString();
    }

    private String applyAction(Detection detection, PolicyAction action) {
        String value = detection.getValue();
        String type = detection.getType();
        return switch (action) {
            case MASK     -> mask(value, type);
            case REMOVE   -> "<" + baseType(type) + "_REDACTED>";
            case HASH     -> hash(value);
            case TOKENIZE -> tokenize(value, type);
            case PARTIAL  -> partial(value, type);
            case ALLOW    -> value;
        };
    }

    private String mask(String value, String type) {
        return switch (baseType(type)) {
            case "SSN" -> {
                String digits = value.replaceAll("[^0-9]", "");
                yield "***-**-" + digits.substring(digits.length() - 4);
            }
            case "CREDIT_CARD" -> {
                String digits = value.replaceAll("[^0-9]", "");
                yield "*".repeat(digits.length() - 4) + digits.substring(digits.length() - 4);
            }
            case "PHONE" -> {
                // keep area code and last 4
                String digits = value.replaceAll("[^0-9]", "");
                if (digits.length() >= 10) {
                    yield digits.substring(0, 3) + "-***-" + digits.substring(digits.length() - 4);
                }
                yield "***-***-" + digits.substring(Math.max(0, digits.length() - 4));
            }
            default -> "[" + baseType(type) + "_MASKED]";
        };
    }

    private String partial(String value, String type) {
        return switch (baseType(type)) {
            case "EMAIL" -> {
                int atIdx = value.indexOf('@');
                if (atIdx <= 0) yield value;
                yield value.charAt(0) + "*".repeat(atIdx - 1) + value.substring(atIdx);
            }
            case "SSN" -> {
                String digits = value.replaceAll("[^0-9]", "");
                yield "***-**-" + digits.substring(digits.length() - 4);
            }
            case "PHONE" -> {
                String digits = value.replaceAll("[^0-9]", "");
                if (digits.length() >= 10) {
                    yield digits.substring(0, 3) + "-***-" + digits.substring(digits.length() - 4);
                }
                yield value;
            }
            default -> mask(value, type);
        };
    }

    private String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hashBytes) hex.append(String.format("%02x", b));
            return "[HASH:" + hex.substring(0, 16) + "]";
        } catch (NoSuchAlgorithmException e) {
            return "[HASH_ERROR]";
        }
    }

    private String tokenize(String value, String type) {
        return tokenStore.computeIfAbsent(
            value,
            k -> "TOKEN_" + baseType(type) + "_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12).toUpperCase()
        );
    }

    private String baseType(String type) {
        return type.contains("/") ? type.substring(0, type.indexOf('/')) : type;
    }
}
