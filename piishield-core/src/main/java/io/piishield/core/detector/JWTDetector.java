package io.piishield.core.detector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JWTDetector implements Detector {

    public static final String TYPE = "JWT";

    // JWTs always start with eyJ (base64 of '{"'), have three dot-separated parts
    private static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[A-Za-z0-9\\-_=]+\\.eyJ[A-Za-z0-9\\-_=]+\\.[A-Za-z0-9\\-_.+/=]*"
    );

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> results = new ArrayList<>();
        if (text == null || text.isEmpty()) return results;

        Matcher matcher = JWT_PATTERN.matcher(text);
        while (matcher.find()) {
            results.add(new Detection(TYPE, matcher.group(), matcher.start(), matcher.end(), 0.99));
        }
        return results;
    }
}
