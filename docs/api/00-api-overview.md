# Open Agent Auth API Documentation

## 📚 Overview

Open Agent Auth provides a framework layer API for implementing Agent Operation Authorization based on industry-standard protocols (OAuth 2.0, OpenID Connect, WIMSE). This documentation focuses on the **framework layer interfaces** that developers should use, including Actor and Executor modules.

### Key Features

- **Actor-Based Architecture**: Independent actor entities (Agent, ResourceServer, AuthorizationServer, UserIdentityProvider, AgentIdentityProvider)
- **Five-Layer Verification**: Comprehensive security validation at Resource Server
- **Workflow Orchestration**: AgentAapExecutor for managing complete authorization flows
- **Spring Boot Integration**: Pre-built HTTP controllers for easy REST API exposure

## 🏗️ Framework Layer Architecture

The framework layer provides high-level abstractions that hide the complexity of the core implementation:

```
Framework Layer (Developer Interface)
├── Actor Module
│   ├── Agent                    - Agent role for authorization requests
│   ├── ResourceServer           - Resource Server with five-layer verification
│   ├── AuthorizationServer      - Authorization Server for token issuance
│   ├── UserIdentityProvider     - User IDP for authentication
│   └── AgentIdentityProvider    - Agent IDP for workload identity management
└── Executor Module
    └── AgentAapExecutor         - Workflow executor for Agent Operation Authorization
```

### Core Layer (Internal Implementation)

The `open-agent-auth-core` module contains internal implementations and should **not** be used directly by developers. All functionality is exposed through framework layer interfaces.

## 🎯 Developer Workflow

### Approach 1: Using Spring Boot Controllers (Recommended)

For Spring Boot applications, use the pre-built REST controllers:

```java
// Controller endpoints are automatically available
@Autowired
private Agent agent;

// Controllers handle HTTP requests and delegate to framework layer
```

**Available Controllers:**
- `UserLoginController` - User authentication
- `WorkloadController` - Workload management
- `OAuth2DcrController` - Dynamic Client Registration
- `OAuth2ParController` - Pushed Authorization Request
- `OAuth2TokenController` - Token issuance
- `OAuth2AuthorizationController` - Authorization endpoints
- `PolicyRegistryController` - Policy management
- `JwksController` - JWKS endpoint

### Approach 2: Using Framework Layer Directly

For non-Spring Boot applications or custom integration, inject framework layer interfaces:

```java
@Autowired
private Agent agent;

@Autowired
private ResourceServer resourceServer;

@Autowired
private AuthorizationServer authorizationServer;
```

### Approach 3: Using AgentAapExecutor

For complete workflow orchestration:

```java
@Autowired
private AgentAapExecutor executor;

// Execute complete authorization flow
String authUrl = executor.initiateUserAuth(authRequest);
// ... continue with executor methods
```

## 📖 API Guides

- [Actor API Guide](01-role-actor.md) - Actor interfaces (Agent, ResourceServer, AuthorizationServer, etc.)
- [Executor API Guide](02-aap-executor.md) - AgentAapExecutor workflow orchestration
- [Spring Boot Controllers Guide](03-spring-boot-starter.md) - REST API endpoints

## 🏗️ Actor Interfaces

### Agent

The `Agent` actor handles authorization requests from the agent side, managing OAuth flows and authorization contexts.

**Key Methods:**
- `initiateAuthorization()` - Start OIDC authorization flow
- `issueWorkloadIdentityToken()` - Issue Workload Identity Token (WIT)
- `registerOAuthClient(WorkloadContext)` - Register OAuth client via DCR (Agent role)
- `submitParRequest()` - Submit Pushed Authorization Request
- `handleAuthorizationCallback()` - Process authorization callback
- `prepareAuthorizationContext()` - Prepare context for tool execution
- `clearAuthorizationContext()` - Clean up resources

**Use Case:** Agent applications requesting authorization to perform operations on behalf of users.

---

### ResourceServer

The `ResourceServer` actor provides five-layer verification for incoming requests.

**Key Methods:**
- `validateRequest()` - Five-layer verification (WIT, WPT, AOAT, Identity Consistency, Policy)
- `logAccess()` - Log access attempts for audit

**Verification Layers:**
1. Workload Authentication (WIT validation)
2. Request Integrity (WPT validation)
3. User Authentication (AOAT validation)
4. Identity Consistency (user-workload binding verification)
5. Policy Evaluation (OPA policy evaluation)

**Use Case:** Resource servers protecting APIs and data with comprehensive security validation.

---

### AuthorizationServer

The `AuthorizationServer` actor handles authorization requests and issues Agent Operation Authorization Tokens (AOAT).

**Key Methods:**
- `registerOAuthClient(String, List<String>)` - Register OAuth client via DCR (Authorization Server role)
- `processParRequest()` - Process Pushed Authorization Request
- `issueAoat()` - Issue Agent Operation Authorization Token

**Use Case:** Authorization servers managing user consent and token issuance.

---

### UserIdentityProvider

The `UserIdentityProvider` actor handles user authentication and ID Token issuance.

**Key Methods:**
- `authenticate()` - Authenticate user and issue ID Token

**Use Case:** User Identity Providers (Agent User IDP, AS User IDP).

---

### AgentIdentityProvider

The `AgentIdentityProvider` actor manages agent workload identities and issues Workload Identity Tokens (WIT).

**Key Methods:**
- `createAgentWorkload()` - Create agent workload with key pair
- `issueWit()` - Issue Workload Identity Token (WIT)
- `revokeAgentWorkload()` - Revoke workload identity

**Use Case:** Agent Identity Providers managing workload lifecycle.

## 🔄 AgentAapExecutor

The `AgentAapExecutor` orchestrates the complete Agent Operation Authorization Protocol (AOA) flow.

**Workflow Steps:**
1. Initiate user authentication
2. Exchange authorization code for ID Token
3. Request authorization URL
4. Exchange authorization code for Agent OA Token
5. Build authorization context
6. Cleanup resources

**Use Case:** Applications needing complete workflow management with simplified API.

## 🚀 Quick Start

### Using Spring Boot Controllers

```java
@Configuration
public class AppConfig {
    
    @Autowired
    private Agent agent;
    
    @GetMapping("/api/authorize")
    public ResponseEntity<?> authorize(@RequestParam String userId) {
        // Use framework layer through controller endpoints
        // Controllers are pre-configured and ready to use
        return ResponseEntity.ok("Authorization initiated");
    }
}
```

### Using Framework Layer Directly

```java
@Service
public class MyService {
    
    @Autowired
    private Agent actor;
    
    @Autowired
    private ResourceServer resourceServer;
    
    public void processRequest(String wit, String wpt, String aoat) {
        // Validate request at Resource Server
        ResourceRequest request = ResourceRequest.builder()
            .wit(wit)
            .wpt(wpt)
            .aoat(aoat)
            .build();
        
        ValidationResult result = resourceServer.validateRequest(request);
        
        if (result.isValid()) {
            // Process request
        }
    }
}
```

## 🔗 Generated Javadoc

For complete API reference, see the auto-generated Javadoc:

- **Framework Module**: [open-agent-auth-framework Javadoc](javadoc/framework/index.html)

## 📚 Additional Resources

- [User Guide](../guide/start/00-user-guide.md) - Comprehensive user guide
- [Configuration Guide](../guide/configuration/) - Detailed configuration options
- [Architecture Documentation](../architecture/) - System architecture details
- [Quick Start Guide](../guide/start/01-quick-start.md) - 5-minute quick start

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](../../LICENSE) file for details.

---

**Version**: 0.1.0-beta.1-SNAPSHOT  
**Last Updated**: 2026-02-08