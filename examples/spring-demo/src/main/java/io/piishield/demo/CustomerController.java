package io.piishield.demo;

import io.piishield.spring.aop.SensitiveData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class CustomerController {

    private static final Logger log = LoggerFactory.getLogger(CustomerController.class);

    // Simulates a customer record with raw PII
    private static final Customer STORED_CUSTOMER = new Customer(
        "John Doe",
        "123-45-6789",
        "john.doe@gmail.com",
        "(630) 555-1234",
        "4532015112830366",
        "AKIAIOSFODNN7EXAMPLE"
    );

    // This endpoint logs the full customer object — PIIShield sanitizes the log automatically
    @PostMapping("/customers")
    public Map<String, String> createCustomer(@RequestBody Customer customer) {
        log.info("Received customer registration: {}", customer);
        log.info("SSN provided: {}", customer.getSsn());
        log.info("Email: {}, Phone: {}", customer.getEmail(), customer.getPhone());
        log.warn("Payment method on file: {}", customer.getCreditCard());

        return Map.of(
            "status", "created",
            "message", "Customer " + customer.getName() + " registered"
        );
    }

    // This endpoint returns sensitive data — @SensitiveData sanitizes the return value
    @GetMapping("/customers/1/summary")
    @SensitiveData
    public String getCustomerSummary() {
        log.info("Fetching customer summary for id=1");
        // In real life this comes from a database — raw PII included
        return STORED_CUSTOMER.toString();
    }

    // This endpoint returns raw JSON — PIIShield filter sanitizes the response body
    @GetMapping("/customers/1/profile")
    public Customer getCustomerProfile() {
        log.info("Fetching full profile for id=1");
        return STORED_CUSTOMER;
    }

    // Demonstrates JWT token interception in a header value being logged
    @GetMapping("/auth/validate")
    public Map<String, String> validateToken(@RequestHeader("Authorization") String authHeader) {
        log.info("Validating token — Authorization header: {}", authHeader);
        return Map.of("valid", "true");
    }
}
