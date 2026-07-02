package io.piishield.core.detector;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CreditCardDetector implements Detector {

    public static final String TYPE = "CREDIT_CARD";

    // Matches 16-digit numbers with optional spaces/dashes between groups of 4
    private static final Pattern CC_PATTERN = Pattern.compile(
        "(?<![\\d])(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[\\s\\-]?" +
        "[0-9]{4}[\\s\\-]?[0-9]{4}[\\s\\-]?[0-9]{4}(?![\\d])" +
        "|(?<![\\d])3[47][0-9]{2}[\\s\\-]?[0-9]{6}[\\s\\-]?[0-9]{5}(?![\\d])"
    );

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public List<Detection> detect(String text) {
        List<Detection> results = new ArrayList<>();
        if (text == null || text.isEmpty()) return results;

        Matcher matcher = CC_PATTERN.matcher(text);
        while (matcher.find()) {
            String match = matcher.group();
            String digits = match.replaceAll("[\\s\\-]", "");
            if (isValidLuhn(digits)) {
                results.add(new Detection(TYPE, match, matcher.start(), matcher.end(), 0.99));
            }
        }
        return results;
    }

    private boolean isValidLuhn(String number) {
        int sum = 0;
        boolean alternate = false;
        for (int i = number.length() - 1; i >= 0; i--) {
            int digit = Character.getNumericValue(number.charAt(i));
            if (alternate) {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }
            sum += digit;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }
}
