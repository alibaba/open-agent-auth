# Spring Boot Controllers Guide

## 📚 Overview

The Open Agent Auth Spring Boot Starter provides pre-built REST controllers that expose the framework layer interfaces as HTTP endpoints. These controllers handle HTTP request/response processing, error handling, and session management, delegating business logic to the framework layer actors and executors.

## 🎯 Design Philosophy

The controllers follow the **Facade Pattern**, providing a clean HTTP layer while keeping authorization logic separate in the framework layer. This allows developers to:

- Use REST APIs without understanding the complex protocol details
- Integrate with web applications easily
- Customize controllers by providing their own implementations
- Leverage Spring Boot auto-configuration

## 🏗️ Controller Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│              Spring Boot Controllers Layer                            │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────────────┐  ┌──────────────────┐  ┌───────────────────┐ │
│  │ UserLoginController │  │ OAuth2Callback   │  │ WorkloadController│ │
│  │   (IDP Role)        │  │   Controller     │  │  (Agent IDP)      │ │
│  └─────────────────────┘  └──────────────────┘  └───────────────────┘ │
│                                                                       │
│  ┌────────────────────┐  ┌──────────────────┐  ┌──────────────┐       │
│  │OAuth2Authorization │  │ OAuth2Dcr        │  │ OAuth2Par    │       │
│  │   Controller       │  │   Controller     │  │   Controller │       │
│  └────────────────────┘  └──────────────────┘  └──────────────┘       │
│                                                                       │
│  ┌──────────────────┐  ┌──────────────────┐  ┌───────────────┐        │
│  │ JwksController   │  │ PolicyRegistry   │  │ Discovery     │        │
│  │   (JWKS Endpoint)│  │   Controller     │  │   Controller  │        │
│  └──────────────────┘  └──────────────────┘  └───────────────┘        │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
                    ↓ Delegates to ↓
┌───────────────────────────────────────────────────────────────────────┐
│              Framework Layer (Actors & Executors)                     │
└───────────────────────────────────────────────────────────────────────┘
```

## 📖 Controller Reference

### 1. UserLoginController

**Role**: User Identity Provider (IDP)  
**Enabled For**: `agent-user-idp`, `as-user-idp`

Handles user authentication and login/logout functionality.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/login` | Login page |
| POST | `/login` | Handle login form submission |
| GET | `/oauth2/logout` | Logout endpoint |
| GET | `/` | Home page |

#### Usage Example

```java
// Redirect to login page
@GetMapping("/secure")
public String securePage() {
    return "redirect:/login";
}

// After successful login, user is redirected to authorization endpoint
```

#### Configuration

```yaml
open-agent-auth:
    role: agent-user-idp  # or as-user-idp
    login:
      enabled: true
```

---

### 2. OAuth2CallbackController

**Role**: Agent, Authorization Server  
**Enabled For**: `agent`, `authorization-server`

Handles OAuth2 callback requests from the authorization server.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/callback` | OAuth2 callback endpoint |

#### Usage Example

```java
// The callback endpoint is automatically configured
// Redirect URL: https://your-app.com/callback?code=xxx&state=yyy

// The controller handles:
// 1. Validating state parameter
// 2. Exchanging authorization code for tokens
// 3. Redirecting to success/error page
```

#### Configuration

```yaml
open-agent-auth:
    role: agent  # or authorization-server
    server:
      callback:
        endpoint: /callback
        client-id: your-client-id
```

---

### 3. WorkloadController

**Role**: Agent Identity Provider (Agent IDP)  
**Enabled For**: `agent-idp`

Manages agent workload identities and WIT issuance.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/workloads/create` | Create agent workload |
| POST | `/api/v1/workloads/issue` | Issue WIT for existing workload |
| POST | `/api/v1/workloads/token/issue` | Issue WIT with automatic workload management |
| POST | `/api/v1/workloads/revoke` | Revoke workload identity |
| POST | `/api/v1/workloads/get` | Get workload information |

#### Usage Example

```java
// Create workload
POST /api/v1/workloads/create
Content-Type: application/json

{
  "idToken": "eyJhbGciOiJSUzI1NiIs...",
  "context": {
    "operationType": "query",
    "resourceId": "product-catalog",
    "metadata": {
      "category": "clothing"
    }
  }
}

// Response
{
  "workloadId": "workload-123",
  "userId": "user-456",
  "publicKey": "-----BEGIN PUBLIC KEY-----...",
  "createdAt": "2026-02-08T10:00:00Z",
  "expiresAt": "2026-02-08T11:00:00Z",
  "status": "active"
}

// Issue WIT
POST /api/v1/workloads/token/issue
Content-Type: application/json

{
  "agent_user_binding_proposal": {
    "user_identity_token": "eyJhbGciOiJSUzI1NiIs..."
  },
  "context": {
    "agent": {
      "client": "sample-agent"
    }
  },
  "publicKey": "-----BEGIN PUBLIC KEY-----..."
}

// Response
{
  "wit": "eyJhbGciOiJSUzI1NiIs..."
}
```

#### Configuration

```yaml
open-agent-auth:
    role: agent-idp
    services:
      provider:
        endpoints:
          workload:
            create: /api/v1/workloads/create
            issue: /api/v1/workloads/issue
            token-issue: /api/v1/workloads/token/issue
            revoke: /api/v1/workloads/revoke
            get: /api/v1/workloads/get
```

---

### 4. OAuth2AuthorizationController

**Role**: Authorization Server, IDP  
**Enabled For**: `authorization-server`, `agent-user-idp`, `as-user-idp`

Handles OAuth 2.0 authorization endpoint.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth2/authorize` | Authorization endpoint |
| POST | `/oauth2/authorize` | Consent submission endpoint |

#### Usage Example

```java
// Redirect to authorization endpoint
// URL: https://your-auth-server.com/oauth2/authorize?request_uri=urn:ietf:params:oauth:request_uri:xxx&state=yyy

// The controller handles:
// 1. PAR request validation
// 2. User authentication (via UserLoginController)
// 3. Consent display
// 4. Token issuance
// 5. Redirect to callback URL
```

#### Configuration

```yaml
open-agent-auth:
    role: authorization-server
    services:
      provider:
        endpoints:
          oauth2:
            authorize: /oauth2/authorize
```

---

### 5. JwksController

**Role**: All Roles  
**Enabled For**: All roles (when `open-agent-auth.enabled=true`)

Provides JWKS endpoint for public key discovery.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/jwks.json` | JWKS endpoint |

#### Usage Example

```bash
# Get JWKS
curl https://your-idp.com/.well-known/jwks.json

# Response
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

#### Configuration

```yaml
open-agent-auth:
    enabled: true
    jwks:
      provider:
        path: /.well-known/jwks.json
        cache-ttl-seconds: 3600
```

---

### 6. OAuth2DcrController

**Role**: Authorization Server  
**Enabled For**: `authorization-server`

Handles Dynamic Client Registration (DCR).

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth2/register` | OAuth client registration |

#### Usage Example

```java
// Register OAuth client
POST /oauth2/register
Content-Type: application/json

{
  "client_assertion": "eyJhbGciOiJSUzI1NiIs...",
  "redirect_uris": [
    "https://client.example.com/callback"
  ],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt"
}

// Response
{
  "client_id": "client-123",
  "client_id_issued_at": 1704729600,
  "registration_access_token": "...",
  "registration_client_uri": "https://auth-server.com/oauth2/register/client-123"
}
```

---

### 7. OAuth2ParController

**Role**: Agent, Authorization Server  
**Enabled For**: `agent`, `authorization-server`

Handles Pushed Authorization Request (PAR).

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth2/par` | PAR submission endpoint |

#### Usage Example

```java
// Submit PAR request
POST /oauth2/par
Content-Type: application/json

{
  "client_assertion": "eyJhbGciOiJSUzI1NiIs...",
  "request": "eyJhbGciOiJSUzI1NiIs..."  // PAR-JWT
}

// Response
{
  "request_uri": "urn:ietf:params:oauth:request_uri:abc123",
  "expires_in": 600
}
```

---

### 8. OAuth2TokenController

**Role**: Authorization Server  
**Enabled For**: `authorization-server`

Handles token issuance.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth2/token` | Token endpoint |

#### Usage Example

```java
// Exchange authorization code for tokens
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=xxx&redirect_uri=https://client.example.com/callback

// Response
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

### 9. PolicyRegistryController

**Role**: Authorization Server  
**Enabled For**: `authorization-server`

Manages OPA policy registration.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/policies` | Register policy |
| GET | `/api/v1/policies/{policyId}` | Get policy |
| DELETE | `/api/v1/policies/{policyId}` | Delete policy |

#### Usage Example

```java
// Register policy
POST /api/v1/policies
Content-Type: application/json

{
  "policyId": "shopping-policy",
  "rego": "package auth\nallow { input.user == input.resource.owner }"
}

// Response
{
  "policyId": "shopping-policy",
  "status": "registered"
}
```

---

### 10. DiscoveryController

**Role**: Authorization Server, IDP  
**Enabled For**: `authorization-server`, `agent-user-idp`, `as-user-idp`

Provides OpenID Connect Discovery endpoint.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/openid-configuration` | Discovery endpoint |

#### Usage Example

```bash
# Get discovery document
curl https://your-idp.com/.well-known/openid-configuration

# Response
{
  "issuer": "https://your-idp.com",
  "authorization_endpoint": "https://your-idp.com/oauth2/authorize",
  "token_endpoint": "https://your-idp.com/oauth2/token",
  "jwks_uri": "https://your-idp.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "subject_types_supported": ["public"]
}
```

---

### 11. OAuth2ConsentController

**Role**: Authorization Server  
**Enabled For**: `authorization-server`

Handles consent page display and submission.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth2/consent` | Consent page |
| POST | `/oauth2/consent` | Consent submission |

---

### 12. OidcUserInfoController

**Role**: Authorization Server, IDP  
**Enabled For**: `authorization-server`, `agent-user-idp`, `as-user-idp`

Provides OIDC UserInfo endpoint.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/oauth2/userinfo` | UserInfo endpoint |

#### Usage Example

```bash
# Get user info
curl -H "Authorization: Bearer xxx" https://your-idp.com/oauth2/userinfo

# Response
{
  "sub": "user-123",
  "name": "John Doe",
  "email": "john@example.com",
  "preferred_username": "johndoe"
}
```

---

### 13. BindingInstanceController

**Role**: Agent IDP  
**Enabled For**: `agent-idp`

Manages binding instances for agent-user binding.

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/bindings` | Create binding instance |
| GET | `/api/v1/bindings/{bindingId}` | Get binding instance |
| DELETE | `/api/v1/bindings/{bindingId}` | Delete binding instance |

---

## 🚀 Quick Start

### 1. Add Dependency

```xml
<dependency>
    <groupId>com.alibaba.openagentauth</groupId>
    <artifactId>open-agent-auth-spring-boot-starter</artifactId>
    <version>0.1.0-beta.1-SNAPSHOT</version>
</dependency>
```

> **Note**: The Open Agent Auth artifacts are not yet published to Maven Central. For now, you need to build the project locally and install it to your local Maven repository:
> ```bash
> git clone https://github.com/alibaba/open-agent-auth.git
> cd open-agent-auth
> mvn clean install -DskipTests
> ```

### 2. Configure Application

```yaml
open-agent-auth:
    role: agent  # or authorization-server, agent-idp, agent-user-idp, as-user-idp
    enabled: true
    server:
      callback:
        endpoint: /callback
        client-id: your-client-id
```

### 3. Use Controllers

```java
@RestController
@RequestMapping("/api")
public class MyController {
    
    @Autowired
    private AgentAapExecutor executor;
    
    @PostMapping("/authorize")
    public ResponseEntity<?> authorize(
            @RequestParam String userId,
            @RequestParam String userOriginalInput) {
        
        // Use executor or call controller endpoints directly
        RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
            .userIdentityToken(idToken)
            .userOriginalInput(userOriginalInput)
            .workloadContext(workloadContext)
            .sessionId(sessionId)
            .build();
        
        RequestAuthUrlResponse response = executor.requestAuthUrl(request);
        
        return ResponseEntity.ok(Map.of(
            "authorizationUrl", response.getAuthorizationUrl(),
            "state", response.getState()
        ));
    }
}
```

---

## 🔧 Configuration

### Controller-Specific Configuration

```yaml
open-agent-auth:
    # General configuration
    enabled: true
    role: agent
    
    # Server configuration
    server:
      callback:
        endpoint: /callback
        client-id: your-client-id
    
    # Services configuration
    services:
      provider:
        endpoints:
          workload:
            create: /api/v1/workloads/create
            issue: /api/v1/workloads/issue
            token-issue: /api/v1/workloads/token/issue
            revoke: /api/v1/workloads/revoke
            get: /api/v1/workloads/get
          oauth2:
            authorize: /oauth2/authorize
    
    # JWKS configuration
    jwks:
      provider:
        path: /.well-known/jwks.json
        cache-ttl-seconds: 3600
    
    # Login configuration
    login:
      enabled: true
```

---

## 🎨 Customization

### Override Controller

```java
@Controller
public class CustomUserLoginController {
    
    @GetMapping("/custom-login")
    public String customLoginPage(Model model) {
        // Custom login page logic
        return "custom-login";
    }
    
    @PostMapping("/custom-login")
    public RedirectView customLogin(
            @RequestParam String username,
            @RequestParam String password) {
        // Custom authentication logic
        return new RedirectView("/home");
    }
}
```

### Customize Login Page

Create `templates/login.html` in your application:

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <form method="post" th:action="@{/login}">
        <input type="hidden" name="redirect_uri" th:value="${redirect_uri}" />
        <div>
            <label>Username:</label>
            <input type="text" name="username" required />
        </div>
        <div>
            <label>Password:</label>
            <input type="password" name="password" required />
        </div>
        <div>
            <button type="submit">Login</button>
        </div>
        <div th:if="${error}" th:text="${error}" style="color: red;"></div>
    </form>
</body>
</html>
```

---

## 📚 Best Practices

### 1. Use HTTPS for All Endpoints

```yaml
server:
  ssl:
    enabled: true
    key-store: classpath:keystore.p12
    key-store-password: changeit
    key-store-type: PKCS12
```

### 2. Configure CORS for Cross-Origin Requests

```java
@Configuration
public class CorsConfig {
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("https://your-frontend.com"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

### 3. Implement Rate Limiting

```java
@Configuration
public class RateLimitConfig {
    
    @Bean
    public FilterRegistrationBean<RateLimitFilter> rateLimitFilter() {
        FilterRegistrationBean<RateLimitFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new RateLimitFilter());
        registration.addUrlPatterns("/oauth2/*", "/api/v1/*");
        return registration;
    }
}
```

### 4. Log Security Events

```java
@Aspect
@Component
public class SecurityLoggingAspect {
    
    private static final Logger logger = LoggerFactory.getLogger(SecurityLoggingAspect.class);
    
    @Around("@annotation(org.springframework.web.bind.annotation.RequestMapping)")
    public Object logSecurityEvent(ProceedingJoinPoint joinPoint) throws Throwable {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        
        logger.info("Security event: method={}, path={}, ip={}", 
                    request.getMethod(), 
                    request.getRequestURI(), 
                    request.getRemoteAddr());
        
        return joinPoint.proceed();
    }
}
```

---

## 🔗 Related Documentation

- [Framework Layer Overview](00-api-overview.md)
- [Actor Interfaces Guide](01-role-actor.md)
- [Executor Interfaces Guide](02-aap-executor.md)
- [User Guide](../guide/start/00-user-guide.md)
- [Configuration Guide](../guide/configuration/)

---

**Version**: 0.1.0-beta.1-SNAPSHOT  
**Last Updated**: 2026-02-08
