package io.piishield.core.detector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SSNDetector implements Detector {

    public static final String TYPE = "SSN";

    // Matches 123-45-6789 and 123456789, but not all-zeros segments
    private static final Pattern SSN_PATTERN = Pattern.compile(
        "(?<![\\d])(?!000|666|9\\d{2})\\d{3}(-?)(?!00)\\d{2}\\1(?!0000)\\d{4}(?![\\d])"
    );

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> results = new ArrayList<>();
        if (text == null || text.isEmpty()) return results;

        Matcher matcher = SSN_PATTERN.matcher(text);
        while (matcher.find()) {
            results.add(new Detection(TYPE, matcher.group(), matcher.start(), matcher.end(), 0.95));
        }
        return results;
    }
}
