package io.piishield.core.detector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class EmailDetector implements Detector {

    public static final String TYPE = "EMAIL";

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"
    );

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> results = new ArrayList<>();
        if (text == null || text.isEmpty()) return results;

        Matcher matcher = EMAIL_PATTERN.matcher(text);
        while (matcher.find()) {
            results.add(new Detection(TYPE, matcher.group(), matcher.start(), matcher.end(), 0.99));
        }
        return results;
    }
}
