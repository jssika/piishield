package io.piishield.core.detector;

public final class Detection {

    private final String type;
    private final String value;
    private final int start;
    private final int end;
    private final double confidence;

    public Detection(String type, String value, int start, int end, double confidence) {
        this.type = type;
        this.value = value;
        this.start = start;
        this.end = end;
        this.confidence = confidence;
    }

    public String getType() { return type; }
    public String getValue() { return value; }
    public int getStart() { return start; }
    public int getEnd() { return end; }
    public double getConfidence() { return confidence; }

    @Override
    public String toString() {
        return "Detection{type='" + type + "', value='[REDACTED]', start=" + start + ", end=" + end + ", confidence=" + confidence + "}";
    }
}
