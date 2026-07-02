package io.piishield.core.detector;

import java.util.List;

public interface Detector {

    String getType();

    List<Detection> detect(String text);
}
