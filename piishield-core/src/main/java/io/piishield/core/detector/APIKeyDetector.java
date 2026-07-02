package io.piishield.core.detector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class APIKeyDetector implements Detector {

    public static final String TYPE = "API_KEY";

    private record KeyPattern(Pattern pattern, String vendor) {}

    private static final List<KeyPattern> PATTERNS = List.of(
        new KeyPattern(Pattern.compile("AKIA[0-9A-Z]{16}"), "AWS_ACCESS_KEY"),
        new KeyPattern(Pattern.compile("(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"), "STRIPE"),
        new KeyPattern(Pattern.compile("sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), "OPENAI"),
        new KeyPattern(Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"), "GOOGLE"),
        new KeyPattern(Pattern.compile("(?i)(?:azure[_\\-]?(?:key|secret|token|api)[_\\-]?(?:id)?[\\s=:\"']+)[0-9a-f\\-]{32,}"), "AZURE"),
        new KeyPattern(Pattern.compile("gh[ps]_[A-Za-z0-9]{36}"), "GITHUB"),
        new KeyPattern(Pattern.compile("xox[baprs]-[0-9A-Za-z\\-]{10,}"), "SLACK")
    );

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> results = new ArrayList<>();
        if (text == null || text.isEmpty()) return results;

        for (KeyPattern kp : PATTERNS) {
            Matcher matcher = kp.pattern().matcher(text);
            while (matcher.find()) {
                results.add(new Detection(TYPE + "/" + kp.vendor(), matcher.group(), matcher.start(), matcher.end(), 0.97));
            }
        }
        return results;
    }
}
