package io.piishield.demo;

public class Customer {
    private String name;
    private String ssn;
    private String email;
    private String phone;
    private String creditCard;
    private String apiKey;

    public Customer() {}

    public Customer(String name, String ssn, String email, String phone, String creditCard, String apiKey) {
        this.name = name;
        this.ssn = ssn;
        this.email = email;
        this.phone = phone;
        this.creditCard = creditCard;
        this.apiKey = apiKey;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getSsn() { return ssn; }
    public void setSsn(String ssn) { this.ssn = ssn; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPhone() { return phone; }
    public void setPhone(String phone) { this.phone = phone; }
    public String getCreditCard() { return creditCard; }
    public void setCreditCard(String creditCard) { this.creditCard = creditCard; }
    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }

    @Override
    public String toString() {
        return "Customer{name='" + name + "', ssn='" + ssn + "', email='" + email +
               "', phone='" + phone + "', creditCard='" + creditCard + "', apiKey='" + apiKey + "'}";
    }
}
