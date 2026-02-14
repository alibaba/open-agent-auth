# Actor Interfaces Guide

## 📚 Overview

The Open Agent Auth framework provides five actor interfaces that define the core responsibilities of different roles in the Agent Operation Authorization Protocol (AOA). Each actor is an independent entity with encapsulated state and behavior, following the Actor Model pattern.

## 🎭 Actor Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Framework Layer Actors                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │    Agent     │  │ResourceServer│  │ AuthzServer  │           │
│  │   (Client)   │  │  (Server)    │  │  (Server)    │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐                             │
│  │   User IDP   │  │  Agent IDP   │                             │
│  │   (Server)   │  │   (Server)   │                             │
│  └──────────────┘  └──────────────┘                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 🏗️ Actor Responsibilities

| Actor | Role | Primary Responsibility |
|-------|------|----------------------|
| **Agent** | Client | Manages authorization requests from the agent side |
| **ResourceServer** | Server | Protects resources with five-layer verification |
| **AuthorizationServer** | Server | Issues Agent Operation Authorization Tokens (AOAT) |
| **UserIdentityProvider** | Server | Handles user authentication and ID Token issuance |
| **AgentIdentityProvider** | Server | Manages agent workload identities and WIT issuance |

---

## 🤖 Agent Actor

### Overview

The `Agent` actor handles authorization requests from the agent side, managing the complete OAuth 2.0 flow with PAR extension. It orchestrates workload creation, OAuth client registration, PAR submission, and authorization context preparation.

### Key Methods

```java
public interface Agent extends FrameworkOAuth2TokenClient {
    
    // Start OIDC authorization flow
    String initiateAuthorization(InitiateAuthorizationRequest request);
    
    // Issue Workload Identity Token (WIT)
    WorkloadContext issueWorkloadIdentityToken(IssueWitRequest request);
    
    // Register OAuth client via DCR (Agent role)
    DcrResponse registerOAuthClient(WorkloadContext workloadContext);
    
    // Submit Pushed Authorization Request
    ParResponse submitParRequest(ParSubmissionRequest request);
    
    // Generate authorization redirect URL
    String generateAuthorizationUrl(String requestUri);
    String generateAuthorizationUrl(String requestUri, String state);
    
    // Handle authorization callback
    AgentOperationAuthToken handleAuthorizationCallback(AuthorizationResponse response);
    
    // Prepare authorization context for tool execution
    AgentAuthorizationContext prepareAuthorizationContext(PrepareAuthorizationContextRequest request);
    
    // Clean up resources
    void clearAuthorizationContext(WorkloadContext workloadContext);
}
```

### Usage Example

```java
@Service
public class AgentService {
    
    @Autowired
    private Agent agent;
    
    public String initiateAuthorizationFlow(String userId, String redirectUri) {
        // Step 1: Initiate authorization
        InitiateAuthorizationRequest request = InitiateAuthorizationRequest.builder()
            .redirectUri(redirectUri)
            .state(generateRandomState())
            .build();
        
        String authUrl = agent.initiateAuthorization(request);
        return authUrl;
    }
    
    public AuthenticationResponse exchangeUserIdToken(String code, String state) {
        // Step 2: Exchange authorization code for ID Token
        ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
            .code(code)
            .state(state)
            .build();
        
        return agent.exchangeCodeForToken(request);
    }
    

    
    public DcrResponse registerOAuthClient(WorkloadContext workloadContext) {
        // Step 3: Register OAuth client
        return agent.registerOAuthClient(workloadContext);
    }
    
    public WorkloadContext issueWorkloadIdentityToken(String idToken, String operationType) {
        // Step 3: Issue Workload Identity Token (WIT)
        IssueWitRequest request = IssueWitRequest.builder()
            .userIdentityToken(idToken)
            .context(AgentRequestContext.builder()
                .operationType(operationType)
                .resourceId("resource-123")
                .metadata(Map.of("key", "value"))
                .build())
            .build();
        
        return agent.issueWorkloadIdentityToken(request);
    }
    
    public ParResponse submitParRequest(WorkloadContext workloadContext, 
                                         String operationProposal, 
                                         Object evidence) {
        // Step 4: Submit PAR request
        ParSubmissionRequest request = ParSubmissionRequest.builder()
            .workloadContext(workloadContext)
            .operationProposal(operationProposal)
            .evidence(evidence)
            .build();
        
        return agent.submitParRequest(request);
    }
    
    public String generateAuthorizationUrl(String requestUri) {
        // Step 5: Generate authorization URL
        return agent.generateAuthorizationUrl(requestUri);
    }
    
    public AgentOperationAuthToken handleCallback(String code, String state) {
        // Step 6: Handle authorization callback
        AuthorizationResponse response = AuthorizationResponse.builder()
            .authorizationCode(code)
            .state(state)
            .build();
        
        return agent.handleAuthorizationCallback(response);
    }
    
    public AgentAuthorizationContext prepareContext(WorkloadContext workloadContext, 
                                                      AgentOperationAuthToken aoat) {
        // Step 7: Prepare authorization context
        PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
            .workloadContext(workloadContext)
            .aoat(aoat)
            .build();
        
        return agent.prepareAuthorizationContext(request);
    }
    
    public void cleanup(WorkloadContext workloadContext) {
        // Step 8: Clean up resources
        agent.clearAuthorizationContext(workloadContext);
    }
}
```

### Complete Workflow

```
User → Agent → Agent User IDP → Agent IDP → Authorization Server → AS User IDP
  │      │          │              │              │                   │
  │      │ 1. initiateAuthorization()                │                   │
  │      ├────────────────────>│              │                   │
  │      │          │              │              │                   │
  │      │ 2. exchangeUserIdToken()                 │                   │
  │      │<─────────────────────│              │                   │
  │      │          │              │              │                   │
  │      │ 3. issueWorkloadIdentityToken()   │              │                   │
  │      │          │────────────────────────────>│                   │
  │      │          │              │              │                   │
  │      │ 4. registerOAuthClient()                │                   │
  │      ├─────────────────────────────────────────────────────────>│
  │      │          │              │              │                   │
  │      │ 5. submitParRequest()                   │                   │
  │      ├─────────────────────────────────────────────────────────>│
  │      │          │              │              │                   │
  │      │ 6. generateAuthorizationUrl()          │                   │
  │      ├─────────────────────────────────────────────────────────>│
  │      │          │              │              │                   │
  │      │          │              │              │ 7. authenticate() │
  │      │          │              │              ├──────────────────>│
  │      │          │              │              │                   │
  │      │ 8. handleAuthorizationCallback()        │                   │
  │      ├─────────────────────────────────────────────────────────>│
  │      │          │              │              │                   │
  │      │ 9. prepareAuthorizationContext()      │                   │
  │      │          │              │              │                   │
  │      │ 10. clearAuthorizationContext()       │                   │
  │      │          │              │              │                   │
```

---

## 🛡️ ResourceServer Actor

### Overview

The `ResourceServer` actor provides five-layer verification for incoming requests, ensuring comprehensive security validation before granting access to protected resources.

### Key Methods

```java
public interface ResourceServer {
    
    // Five-layer verification
    ValidationResult validateRequest(ResourceRequest request);
    
    // Log access attempts
    void logAccess(AuditLogEntry auditLog);
}
```

### Five-Layer Verification Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Five-Layer Verification                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Layer 1: Workload Authentication (WIT validation)              │
│  - Validate WIT signature                                        │
│  - Check WIT claims (iss, sub, exp, aud, cnf)                   │
│                                                                  │
│  Layer 2: Request Integrity (WPT validation)                    │
│  - Verify WPT signature using WIT's public key                   │
│  - Check request integrity                                       │
│                                                                  │
│  Layer 3: User Authentication (AOAT validation)                 │
│  - Validate AOAT signature                                       │
│  - Extract user ID and policy ID                                │
│                                                                  │
│  Layer 4: Identity Consistency                                   │
│  - Verify user-workload binding (user_id == workload.user)       │
│                                                                  │
│  Layer 5: Policy Evaluation                                      │
│  - Evaluate OPA policy with request context                      │
│  - Return authorization decision (allow/deny)                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Usage Example

```java
@RestController
@RequestMapping("/api/resources")
public class ResourceController {
    
    @Autowired
    private ResourceServer resourceServer;
    
    @GetMapping("/{resourceId}")
    public ResponseEntity<?> getResource(
            @PathVariable String resourceId,
            @RequestHeader("X-Workload-Identity") String wit,
            @RequestHeader("X-Workload-Proof") String wpt,
            @RequestHeader("Authorization") String aoat) {
        
        // Build resource request
        ResourceRequest request = ResourceRequest.builder()
            .wit(wit)
            .wpt(wpt)
            .aoat(aoat)
            .resourceId(resourceId)
            .operation("read")
            .build();
        
        // Validate request using five-layer verification
        ValidationResult result = resourceServer.validateRequest(request);
        
        if (!result.isValid()) {
            // Log access attempt
            AuditLogEntry auditLog = AuditLogEntry.builder()
                .userId(result.getUserId())
                .workloadId(result.getWorkloadId())
                .resourceId(resourceId)
                .operation("read")
                .decision(AuditDecision.DENIED)
                .reason(result.getFailureReason())
                .timestamp(Instant.now())
                .build();
            
            resourceServer.logAccess(auditLog);
            
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body("Access denied: " + result.getFailureReason());
        }
        
        // Access granted - return resource
        Object resource = getResourceById(resourceId);
        
        // Log successful access
        AuditLogEntry auditLog = AuditLogEntry.builder()
            .userId(result.getUserId())
            .workloadId(result.getWorkloadId())
            .resourceId(resourceId)
            .operation("read")
            .decision(AuditDecision.ALLOW)
            .timestamp(Instant.now())
            .build();
        
        resourceServer.logAccess(auditLog);
        
        return ResponseEntity.ok(resource);
    }
}
```

### Validation Result Structure

```java
public class ValidationResult {
    private boolean valid;
    private String userId;
    private String workloadId;
    private String failureReason;
    private Map<String, Object> layerResults;
    
    // Layer-specific validation results
    private boolean witValid;
    private boolean wptValid;
    private boolean aoatValid;
    private boolean identityConsistent;
    private boolean policyAllowed;
}
```

---

## 🔐 AuthorizationServer Actor

### Overview

The `AuthorizationServer` actor handles authorization requests, manages user authorization, and issues Agent Operation Authorization Tokens (AOAT). It implements OAuth 2.0 Dynamic Client Registration (DCR) and Pushed Authorization Request (PAR) protocols.

### Key Methods

```java
public interface AuthorizationServer extends FrameworkOAuth2TokenClient, FrameworkOAuth2TokenServer {
    
    // Process Pushed Authorization Request
    ParResponse processParRequest(ParRequest parRequest);
    
    // Issue Agent Operation Authorization Token
    AgentOperationAuthToken issueAoat(AoatIssuanceRequest request);
    
    // Register OAuth client via DCR (Authorization Server role)
    DcrResponse registerOAuthClient(String clientAssertion, List<String> redirectUris);
}
```

### Usage Example

```java
@Service
public class AuthorizationService {
    
    @Autowired
    private AuthorizationServer authorizationServer;
    
    public DcrResponse registerOAuthClient(String wit, List<String> redirectUris) {
        // Register OAuth client using DCR
        return authorizationServer.registerOAuthClient(wit, redirectUris);
    }
    
    public ParResponse processParRequest(ParRequest request) {
        // Process PAR request
        return authorizationServer.processParRequest(request);
    }
    
    public AgentOperationAuthToken issueAoat(AoatIssuanceRequest request) {
        // Issue Agent OA Token
        return authorizationServer.issueAoat(request);
    }
}
```

### DCR Workflow

```
Agent → Authorization Server → JWKS Endpoint
  │           │                    │
  │ 1. registerOAuthClient(WIT)   │
  ├──────────────────────────────>│
  │           │                    │
  │           │ 2. Get public key  │
  │           ├───────────────────>│
  │           │                    │
  │           │ 3. Return public key
  │           │<───────────────────│
  │           │                    │
  │           │ 4. Validate WIT    │
  │           │ 5. Register client │
  │           │    (client_id = WIT.sub)
  │           │                    │
  │ 6. Return DcrResponse         │
  │<──────────────────────────────│
```

---

## 👤 UserIdentityProvider Actor

### Overview

The `UserIdentityProvider` actor handles user authentication and ID Token issuance. Both Agent User IDP and AS User IDP implement this interface with their specific authentication strategies.

### Key Methods

```java
public interface UserIdentityProvider extends FrameworkOAuth2TokenServer {
    
    // Authenticate user and issue ID Token
    AuthenticationResponse authenticate(AuthenticationRequest request);
}
```

### Usage Example

```java
@Service
public class UserAuthenticationService {
    
    @Autowired
    private UserIdentityProvider userIdentityProvider;
    
    public AuthenticationResponse authenticateUser(String username, String password) {
        AuthenticationRequest request = AuthenticationRequest.builder()
            .username(username)
            .password(password)
            .build();
        
        return userIdentityProvider.authenticate(request);
    }
}
```

### Authentication Flow

```
Client → User IDP Service → Core Module
  │           │                 │
  │ 1. authenticate(request)   │
  ├──────────────────────────>│
  │           │                 │
  │           │ 2. Validate credentials
  │           ├────────────────>│
  │           │                 │
  │           │ 3. Return IdToken
  │           │<────────────────│
  │           │                 │
  │ 4. Format Response         │
  │           │ 5. Return AuthResponse
  │<──────────────────────────│
```

---

## 🤖 AgentIdentityProvider Actor

### Overview

The `AgentIdentityProvider` actor manages agent workload identities and issues Workload Identity Tokens (WIT). It extends standard WIMSE Workload IDP capabilities with agent-specific functionality.

### Key Methods

```java
public interface AgentIdentityProvider {
    
    // Create agent workload
    WorkloadInfo createAgentWorkload(String idToken, AgentRequestContext context);
    
    // Issue Workload Identity Token
    WorkloadIdentityToken issueWit(String agentWorkloadId);
    WorkloadIdentityToken issueWit(IssueWitRequest request);
    
    // Revoke agent workload
    void revokeAgentWorkload(String agentWorkloadId);
    
    // Get agent workload information
    WorkloadInfo getAgentWorkload(String agentWorkloadId);
}
```

### Usage Example

```java
@Service
public class AgentWorkloadService {
    
    @Autowired
    private AgentIdentityProvider agentIdentityProvider;
    
    public WorkloadInfo createWorkload(String idToken, String operationType) {
        AgentRequestContext context = AgentRequestContext.builder()
            .operationType(operationType)
            .resourceId("resource-123")
            .metadata(Map.of("key", "value"))
            .build();
        
        return agentIdentityProvider.createAgentWorkload(idToken, context);
    }
    
    public WorkloadIdentityToken issueWit(String workloadId) {
        return agentIdentityProvider.issueWit(workloadId);
    }
    
    public void revokeWorkload(String workloadId) {
        agentIdentityProvider.revokeAgentWorkload(workloadId);
    }
}
```

### WIT Structure

```json
{
  "iss": "wimse://example.com",
  "sub": "agent-instance-123",
  "exp": 1704067200,
  "jti": "wit-abc123",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  }
}
```

---

## 🔄 Actor Interactions

### Complete AOA Flow with All Actors

```
┌─────────────────────────────────────────────────────────────────┐
│              Complete Actor Interaction Flow                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Agent initiates user authentication                         │
│     AgentAapExecutor.initiateUserAuth() → Agent User IDP         │
│                                                                  │
│  2. Agent exchanges authorization code for ID Token             │
│     AgentAapExecutor.exchangeUserIdToken() → Agent User IDP      │
│                                                                  │
│  3. Agent requests authorization URL                            │
│     AgentAapExecutor.requestAuthUrl() → AgentIdentityProvider    │
│     └─> Creates workload, issues WIT, registers OAuth client     │
│     └─> Submits PAR, generates authorization URL                 │
│                                                                  │
│  4. User authenticates and authorizes                            │
│     AuthorizationServer → UserIdentityProvider                   │
│                                                                  │
│  5. Agent exchanges authorization code for AOAT                  │
│     AgentAapExecutor.exchangeAgentAuthToken() → AuthorizationServer│
│                                                                  │
│  6. Agent builds authorization context                           │
│     AgentAapExecutor.buildAuthContext()                          │
│                                                                  │
│  7. ResourceServer validates request                            │
│     ResourceServer.validateRequest()                             │
│                                                                  │
│  8. Agent cleans up resources                                   │
│     AgentAapExecutor.cleanup() → AgentIdentityProvider           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📚 Best Practices

### 1. Always Clean Up Resources

```java
try {
    // Perform authorization flow
    AgentAuthorizationContext context = agent.prepareAuthorizationContext(request);
    // Use context
} finally {
    // Always clean up
    agent.clearAuthorizationContext(workloadContext);
}
```

### 2. Validate Input Parameters

```java
public WorkloadContext issueWorkloadIdentityToken(
        OperationRequestContext context,
        AgentUserBindingProposal proposal,
        String oauthClientId) {
    Objects.requireNonNull(context, "Context must not be null");
    Objects.requireNonNull(proposal, "Proposal must not be null");
    Objects.requireNonNull(oauthClientId, "OAuth client ID must not be null");
    
    return agent.issueWorkloadIdentityToken(IssueWitRequest.builder()
        .context(context)
        .proposal(proposal)
        .oauthClientId(oauthClientId)
        .build());
}
```

### 3. Handle Exceptions Gracefully

```java
try {
    ValidationResult result = resourceServer.validateRequest(request);
} catch (FrameworkValidationException e) {
    log.error("Validation failed", e);
    throw new AuthorizationException("Unable to validate request", e);
}
```

### 4. Log Security Events

```java
AuditLogEntry auditLog = AuditLogEntry.builder()
    .userId(userId)
    .workloadId(workloadId)
    .resourceId(resourceId)
    .operation(operation)
    .decision(decision)
    .timestamp(Instant.now())
    .build();

resourceServer.logAccess(auditLog);
```

---

## 🔗 Related Documentation

- [Framework Layer Overview](00-api-overview.md)
- [Executor Interfaces Guide](02-aap-executor.md)
- [Spring Boot Controllers Guide](03-spring-boot-starter.md)
- [User Guide](../guide/start/00-user-guide.md)
- [Configuration Guide](../guide/configuration/)

---

**Version**: 0.1.0-beta.1-SNAPSHOT  
**Last Updated**: 2026-02-08
