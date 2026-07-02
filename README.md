# PIIShield

**Runtime Privacy Protection for Modern Enterprise Applications**

PIIShield intercepts PII, secrets, and credentials *before* they leave your application — before they reach Datadog, Splunk, CloudWatch, or any other logging and monitoring platform. No code changes required.

---

## The Problem

Enterprise applications log millions of events every day. Developers routinely log entire request payloads, exception objects, customer DTOs, HTTP headers, and JWT tokens. Once that data reaches an observability platform, it is difficult to remove and may create compliance and security risks.

PIIShield stops sensitive data at the source.

---

## How It Works

```
Enterprise Application
        │
        ▼
  PIIShield Runtime SDK
  ┌────────────────────────┐
  │  Detection Engine      │  ← regex + Luhn validation
  │  Policy Engine         │  ← YAML-driven rules
  │  Redaction Engine      │  ← MASK / REMOVE / HASH / TOKENIZE / PARTIAL
  │  Audit Engine          │  ← structured event log
  └────────────────────────┘
        │
        ▼
  Sanitized Output → Logs / Monitoring / Queue
```

---

## Quickstart — Spring Boot

Add one dependency:

```xml
<dependency>
    <groupId>io.piishield</groupId>
    <artifactId>piishield-spring</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Restart your application. Done.

PIIShield auto-configures a servlet filter, Logback appender, and AOP interceptor. All sensitive data is sanitized before it reaches any log output or HTTP response body.

---

## Configuration

Override defaults in `application.yml`:

```yaml
piishield:
  enabled: true

  detectors:
    ssn:
      enabled: true
      action: MASK          # ***-**-6789
    email:
      enabled: true
      action: PARTIAL       # j***@gmail.com
    phone:
      enabled: true
      action: MASK          # 630-***-1234
    credit_card:
      enabled: true
      action: MASK          # ************1234
    jwt:
      enabled: true
      action: REMOVE        # <JWT_REDACTED>
    api_key:
      enabled: true
      action: REMOVE        # <API_KEY_REDACTED>

  filter:
    enabled: true
    sanitize-request-body: true
    sanitize-response-body: true
    sanitize-headers: true

  logback:
    enabled: true

  aop:
    enabled: true
```

---

## Redaction Actions

| Action     | Example output                        | Description                          |
|------------|---------------------------------------|--------------------------------------|
| `MASK`     | `***-**-6789`                         | Hides most content, keeps last digits |
| `PARTIAL`  | `j***@gmail.com`                      | Shows first/last segment             |
| `REMOVE`   | `<SSN_REDACTED>`                      | Replaces with a typed placeholder    |
| `HASH`     | `[HASH:3d4f8a2c1b9e0f7a]`            | SHA-256 (first 16 hex chars)         |
| `TOKENIZE` | `TOKEN_SSN_A3F9C12B0E4D`             | Stable opaque token (in-memory)      |
| `ALLOW`    | *(unchanged)*                         | Passes through without modification  |

---

## What PIIShield Detects

| Type          | Examples detected                                         |
|---------------|-----------------------------------------------------------|
| SSN           | `123-45-6789`, `123456789`                               |
| Email         | `john@example.com`, `user+tag@company.co.uk`            |
| Phone         | `(630) 555-1234`, `630-555-1234`, `+1 630 555 1234`     |
| Credit Card   | Visa, Mastercard, Amex, Discover — validated with Luhn  |
| JWT           | `eyJ...` three-part bearer tokens                        |
| API Keys      | AWS, Stripe, OpenAI, Google, GitHub, Slack               |

---

## Spring Boot Interceptors

PIIShield wires up four interception points automatically:

### 1. Logback Appender
Wraps all root logger appenders. Every log message is sanitized before it reaches any output (console, file, Datadog, etc.).

```
logger.info("Processing customer: {}", customer.toString());
// → Processing customer: {name: John, ssn: ***-**-6789, email: j***@gmail.com}
```

### 2. Servlet Filter
Sanitizes HTTP response bodies. Sanitized header values are stored as request attributes for downstream logging.

### 3. Handler Interceptor
Sanitizes Spring MVC model attributes before they are rendered or serialized.

### 4. `@SensitiveData` AOP Annotation
Marks individual service or repository methods whose `String` return values should be sanitized:

```java
@SensitiveData
public String getCustomerSummary(long id) {
    return customerRepo.getRawSummary(id); // any PII is scrubbed before the caller sees it
}
```

---

## Using Core Without Spring

`piishield-core` has no framework dependencies and can be used standalone:

```java
// Default config (all detectors enabled with sensible actions)
PIIShieldEngine engine = PIIShieldEngine.withDefaults();

String sanitized = engine.sanitizeQuick("SSN: 123-45-6789, card: 4532015112830366");
// → "SSN: ***-**-6789, card: ************0366"

// Full result with audit trail
SanitizeResult result = engine.sanitize(text);
result.isModified();        // true
result.getSanitizedText();  // sanitized string
result.getEvents();         // List<AuditEvent> — what was found and what action was taken
```

Load policy from YAML:

```java
PIIShieldEngine engine = PIIShieldEngine.fromYaml(
    getClass().getResourceAsStream("/piishield.yml")
);
```

Build with a custom policy:

```java
PIIShieldConfig config = new PIIShieldConfig();
config.getDetectors().put("SSN", new DetectorPolicy(true, PolicyAction.HASH));

PIIShieldEngine engine = new PIIShieldEngine.Builder()
    .policyEngine(new PolicyEngine(config))
    .build();
```

---

## Audit Events

Every redaction produces a structured audit event:

```json
{
  "type": "SSN",
  "action": "MASK",
  "location": "text",
  "confidence": 0.95,
  "timestamp": "2026-07-01T03:14:00Z"
}
```

Attach a listener to stream events in real time:

```java
engine.getAuditEngine().setListener(event ->
    auditLog.write(event.toString())
);
```

---

## Extending with Custom Detectors

Implement the `Detector` interface and register it:

```java
public class PassportDetector implements Detector {
    private static final Pattern PATTERN = Pattern.compile("[A-Z]{1}[0-9]{8}");

    @Override
    public String getType() { return "PASSPORT"; }

    @Override
    public List<Detection> detect(String text) {
        // find matches and return Detection objects with start/end indices
    }
}

PIIShieldEngine engine = new PIIShieldEngine.Builder()
    .addDetector(new PassportDetector())
    .build();
```

---

## Project Structure

```
piishield/
├── piishield-core/          # Framework-agnostic engine
│   └── src/main/java/io/piishield/core/
│       ├── PIIShieldEngine.java
│       ├── SanitizeResult.java
│       ├── detector/        # Detector interface + 6 built-in detectors
│       ├── policy/          # PolicyEngine, PolicyAction, PIIShieldConfig
│       ├── redaction/       # RedactionEngine
│       └── audit/           # AuditEngine, AuditEvent
│
└── piishield-spring/        # Spring Boot auto-configuration
    └── src/main/java/io/piishield/spring/
        ├── config/          # PIIShieldAutoConfiguration, PIIShieldProperties
        ├── filter/          # PIIShieldFilter (servlet)
        ├── interceptor/     # PIIShieldHandlerInterceptor
        ├── aop/             # @SensitiveData, PIIShieldAspect
        └── logback/         # PIIShieldLogbackAppender
```

---

## Building

```bash
mvn clean test
```

Requires Java 17+ and Maven 3.8+.

---

## Roadmap

| Version | Features |
|---------|----------|
| **v0.1** | Java SDK — SSN, Email, Phone, Credit Card, JWT, API Keys. Spring Boot auto-configuration. |
| v0.2 | OAuth tokens, secrets scanning, JSON-aware reports |
| v0.3 | Kafka interceptor, gRPC, REST client/server |
| v0.4 | Python SDK |
| v0.5 | Node.js SDK |
| v1.0 | Central policy server, AI-assisted detection, dashboard |

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
