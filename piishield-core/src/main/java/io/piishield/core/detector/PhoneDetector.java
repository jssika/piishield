package io.piishield.core.detector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PhoneDetector implements Detector {

    public static final String TYPE = "PHONE";

    // Matches US/CA formats: (630) 555-1234, 630-555-1234, +1 630 555 1234, 6305551234
    private static final Pattern PHONE_PATTERN = Pattern.compile(
        "(?:(?:\\+1[\\s.\\-]?)?(?:\\(?[2-9]\\d{2}\\)?)[\\s.\\-]?[2-9]\\d{2}[\\s.\\-]?\\d{4})(?!\\d)"
    );

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> results = new ArrayList<>();
        if (text == null || text.isEmpty()) return results;

        Matcher matcher = PHONE_PATTERN.matcher(text);
        while (matcher.find()) {
            String match = matcher.group().trim();
            results.add(new Detection(TYPE, match, matcher.start(), matcher.end(), 0.85));
        }
        return results;
    }
}
