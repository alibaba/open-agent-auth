# Sample Authorization Server

A complete OAuth 2.0 Authorization Server implementation for Agent Operation Authorization (AOA) protocol.

## 🌟 Features

- **OAuth 2.0 Authorization Code Flow** with Pushed Authorization Requests (PAR)
- **Dynamic Client Registration (DCR)** according to RFC 7591
- **Agent Operation Authorization Token (AOAT)** issuance
- **Beautiful, Professional UI** for user authentication and consent
- **Extensible Architecture** with pluggable authentication and consent providers
- **Zero Configuration** - Works out of the box with sensible defaults

## 🚀 Quick Start

### Prerequisites

- Java 17 or higher
- Maven 3.6 or higher

### Running the Server

```bash
# Clone the repository
git clone <repository-url>
cd open-agent-auth/open-agent-auth-samples/sample-authorization-server

# Build the project
mvn clean package

# Run the server
mvn spring-boot:run
```

The server will start on port **8085**.

### Accessing Endpoints

- **Authorization Endpoint**: `http://localhost:8085/oauth2/authorize`
- **Token Endpoint**: `http://localhost:8085/oauth2/token`
- **PAR Endpoint**: `http://localhost:8085/par`
- **DCR Endpoint**: `http://localhost:8085/oauth2/register`
- **Discovery Endpoint**: `http://localhost:8085/.well-known/oauth-authorization-server`
- **JWKS Endpoint**: `http://localhost:8085/.well-known/jwks.json`

## 🎨 UI Screenshots

### Login Page
A clean, modern login interface with gradient design and smooth animations.

### Consent Page
Professional authorization consent page showing:
- Client ID and user information
- Requested permissions (scopes)
- Security notice
- Approve/Deny actions

## 📖 Configuration

### Application Configuration

Edit `src/main/resources/application.yml`:

```yaml
server:
  port: 8085

open-agent-auth:
  enabled: true
  issuer: http://localhost:8085
  
  server:
    par:
      enabled: true
      endpoint: /par
      request-expiry: 90
    
    token:
      enabled: true
      endpoint: /oauth2/token
      access-token-expiry: 3600
    
    authorization:
      enabled: true
      endpoint: /oauth2/authorize
      code-expiry: 600
      consent-required: true
    
    dcr:
      enabled: true
      endpoint: /oauth2/register
```

### Enabling/Disabling Features

You can enable or disable specific endpoints by setting the `enabled` property:

```yaml
open-agent-auth:
  server:
    dcr:
      enabled: false  # Disable Dynamic Client Registration
```

## 🔧 Customization

### Custom Authentication Provider

Implement `UserAuthenticationProvider` to add your own authentication logic:

```java
@Component
public class CustomUserAuthenticationProvider implements UserAuthenticationProvider {
    @Override
    public String authenticate(HttpServletRequest request) {
        // Your custom authentication logic
        return "user-id";
    }
}
```

### Custom Consent Page Provider

Implement `ConsentPageProvider` to customize the consent page:

```java
@Component
public class CustomConsentPageProvider implements ConsentPageProvider {
    @Override
    public ModelAndView renderConsentPage(
            HttpServletRequest request,
            String requestUri,
            String subject,
            String clientId,
            String scopes
    ) {
        // Your custom consent page logic
        return new ModelAndView("custom-consent");
    }
}
```

## 📚 Protocol Support

### OAuth 2.0 Authorization Code Flow

1. **Push Authorization Request (PAR)** - RFC 9126
   - POST `/par` with authorization parameters
   - Returns `request_uri` for authorization endpoint

2. **Authorization** - RFC 6749
   - GET `/oauth2/authorize?request_uri=...`
   - User authentication and consent
   - Returns authorization code

3. **Token Request** - RFC 6749
   - POST `/oauth2/token` with authorization code
   - Returns Agent Operation Authorization Token (AOAT)

### Dynamic Client Registration (DCR) - RFC 7591

- **Register Client**: POST `/oauth2/register`
- **Read Client**: GET `/oauth2/register/{clientId}`
- **Update Client**: PUT `/oauth2/register/{clientId}`
- **Delete Client**: DELETE `/oauth2/register/{clientId}`

## 🔐 Security Features

- **Session-based Authentication** with CSRF protection
- **Secure Token Generation** using RSA keys
- **Token Validation** with signature verification
- **Consent Tracking** for audit trail
- **Configurable Expiration** for all tokens

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Spring Boot Starter Layer                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Standard Protocol Controllers                      │  │
│  │  - OAuth2ParController                              │  │
│  │  - OAuth2TokenController                            │  │
│  │  - OAuth2DcrController                              │  │
│  │  - OAuth2AuthorizationController                    │  │
│  │  - DiscoveryController                              │  │
│  │  - JwksController                                   │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Extension Points                                  │  │
│  │  - UserAuthenticationProvider                      │  │
│  │  - ConsentPageProvider                             │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│  Sample Layer                                            │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Business Controllers                               │  │
│  │  - LoginController                                 │  │
│  │  - ConsentController                               │  │
│  │  - Custom implementations of extension points       │  │
│  └───────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────┐  │
│  │  UI Templates                                      │  │
│  │  - login.html                                      │  │
│  │  - consent.html                                │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 🧪 Testing

### Test the Authorization Flow

1. **Register a Client**:
```bash
curl -X POST http://localhost:8085/oauth2/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:3000/callback"],
    "client_name": "Test Client",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "openid profile"
  }'
```

2. **Create Authorization Request**:
```bash
curl -X POST http://localhost:8085/par \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "request=<JWT>"
```

3. **Authorize**: Open the returned `request_uri` in a browser

4. **Get Token**: Use the authorization code to get an AOAT

## 📝 Example Usage

### Java Client

```java
// Register client
DcrResponse client = dcrServer.registerClient(DcrRequest.builder()
    .redirectUris(List.of("http://localhost:3000/callback"))
    .clientName("My App")
    .build());

// Create PAR request
ParResponse par = parServer.processParRequest(parRequest, client.getClientId());

// Authorize (redirect user to browser)
String authUrl = "http://localhost:8085/oauth2/authorize?request_uri=" + par.getRequestUri();

// Exchange code for token
TokenResponse token = tokenServer.issueToken(tokenRequest);
```

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## 📄 License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with [open-agent-auth](https://github.com/alibaba/open-agent-auth) framework
- Follows OAuth 2.0 and OpenID Connect specifications
- Inspired by industry best practices for authorization servers

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Note**: This is a sample implementation for demonstration purposes. For production use, ensure proper security configurations, TLS/SSL setup, and integration with your identity provider.
