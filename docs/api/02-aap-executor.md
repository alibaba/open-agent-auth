# Executor Interfaces Guide

## 📚 Overview

The `AgentAapExecutor` is a high-level workflow executor that orchestrates the complete Agent Operation Authorization Protocol (AOA) flow. It provides a simplified API for managing the authorization lifecycle from user authentication to context preparation and cleanup.

## 🎯 Design Philosophy

The executor follows the **Workflow Orchestration Pattern**, encapsulating the complexity of multiple actor interactions into a single, easy-to-use interface. This allows developers to focus on business logic rather than protocol details.

### Key Benefits

- **Simplified API**: Single interface for complete authorization flow
- **State Management**: Automatic management of authorization state
- **Error Handling**: Built-in error handling and recovery
- **Resource Cleanup**: Automatic cleanup after operation completion

## 🔄 Complete Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│              AgentAapExecutor Complete Workflow                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Step 1: Initiate User Authentication                           │
│  └─ initiateUserAuth() → Returns authorization URL              │
│                                                                  │
│  Step 2: Exchange Authorization Code for ID Token                │
│  └─ exchangeUserIdToken() → Returns executor with ID Token      │
│                                                                  │
│  Step 3: Request Authorization URL                               │
│  └─ requestAuthUrl() → Returns authorization URL + context      │
│                                                                  │
│  Step 4: Exchange Authorization Code for Agent OA Token          │
│  └─ exchangeAgentAuthToken() → Returns AOAT                     │
│                                                                  │
│  Step 5: Build Authorization Context                             │
│  └─ buildAuthContext() → Returns WIT, WPT, AOAT                │
│                                                                  │
│  Step 6: Get Workload Context                                   │
│  └─ getWorkloadContext() → Returns workload context             │
│                                                                  │
│  Step 7: Cleanup Resources                                       │
│  └─ cleanup() → Revokes workload and clears data                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## 🏗️ Executor Interface

```java
public interface AgentAapExecutor {
    
    // Step 1: Initiate user authentication
    String initiateUserAuth(InitiateAuthorizationRequest request);
    
    // Step 2: Exchange authorization code for ID Token
    AgentAapExecutor exchangeUserIdToken(ExchangeCodeForTokenRequest request);
    
    // Step 3: Request authorization URL
    RequestAuthUrlResponse requestAuthUrl(RequestAuthUrlRequest request);
    
    // Step 4: Exchange authorization code for Agent OA Token
    AgentOperationAuthToken exchangeAgentAuthToken(AuthorizationResponse response);
    
    // Step 5: Build authorization context
    AgentAuthorizationContext buildAuthContext(PrepareAuthorizationContextRequest contextRequest);
    
    // Step 6: Get workload context for cleanup
    WorkloadContext getWorkloadContext();
    
    // Step 7: Cleanup resources
    void cleanup(WorkloadContext workloadContext);
}
```

---

## 📖 Detailed Method Guide

### Step 1: Initiate User Authentication

**Method**: `String initiateUserAuth(InitiateAuthorizationRequest request)`

**Purpose**: Starts the OIDC authorization flow by generating the authorization URL.

**Parameters**:
- `redirectUri`: The callback URL where the authorization code will be sent
- `state`: A random value to prevent CSRF attacks

**Returns**: The authorization URL to redirect the user to

**Example**:
```java
InitiateAuthorizationRequest request = InitiateAuthorizationRequest.builder()
    .redirectUri("https://example.com/callback")
    .state(generateRandomState())
    .build();

String authUrl = executor.initiateUserAuth(request);
// Redirect user to authUrl
```

---

### Step 2: Exchange Authorization Code for ID Token

**Method**: `AgentAapExecutor exchangeUserIdToken(ExchangeCodeForTokenRequest request)`

**Purpose**: Exchanges the authorization code for an ID Token.

**Parameters**:
- `code`: The authorization code received from the callback
- `state`: The state parameter for CSRF validation

**Returns**: The updated executor instance with ID Token

**Example**:
```java
ExchangeCodeForTokenRequest request = ExchangeCodeForTokenRequest.builder()
    .code(authorizationCode)
    .state(state)
    .build();

executor = executor.exchangeUserIdToken(request);
// Executor now has ID Token internally stored
```

---

### Step 3: Request Authorization URL

**Method**: `RequestAuthUrlResponse requestAuthUrl(RequestAuthUrlRequest request)`

**Purpose**: Aggregates the complete authorization URL request flow, performing:
- Workload creation
- WIT issuance
- OAuth Client Registration (DCR)
- PAR construction and submission
- Auth URL construction

**Parameters**:
- `userIdentityToken`: The user's ID Token from Agent User IDP (REQUIRED)
- `userOriginalInput`: The user's original natural language input (REQUIRED)
- `workloadContext`: The workload context containing operation type, resource info, etc.
- `sessionId`: Session identifier for CSRF protection

**Returns**: `RequestAuthUrlResponse` containing:
- `authorizationUrl`: The authorization redirect URL
- `requestUri`: The PAR request URI
- `state`: The state parameter
- `workloadContext`: The workload context for later use

**Example**:
```java
WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
    .operationType("query")
    .resourceId("product-catalog")
    .metadata(Map.of("category", "clothing"))
    .build();

RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
    .userIdentityToken(idToken)
    .userOriginalInput("I want to buy winter clothes, please give me some suggestions")
    .workloadContext(workloadContext)
    .sessionId(sessionId)
    .build();

RequestAuthUrlResponse response = executor.requestAuthUrl(request);

// Store state and workloadContext for callback handling
session.setAttribute("oauth_state", response.getState());
session.setAttribute("workload_context", response.getWorkloadContext());

// Redirect user to authorization URL
return ResponseEntity.status(HttpStatus.FOUND)
    .location(URI.create(response.getAuthorizationUrl()))
    .build();
```

---

### Step 4: Exchange Authorization Code for Agent OA Token

**Method**: `AgentOperationAuthToken exchangeAgentAuthToken(AuthorizationResponse response)`

**Purpose**: Exchanges the authorization code for an Agent Operation Authorization Token (AOAT).

**Parameters**:
- `authorizationCode`: The authorization code from the callback
- `state`: The state parameter for CSRF validation

**Returns**: The Agent Operation Authorization Token (AOAT)

**Example**:
```java
// In callback endpoint
@GetMapping("/callback")
public ResponseEntity<?> handleCallback(
        @RequestParam("code") String code,
        @RequestParam("state") String state) {
    
    // Validate state
    String storedState = session.getAttribute("oauth_state");
    if (!state.equals(storedState)) {
        throw new IllegalStateException("Invalid state parameter");
    }
    
    // Exchange authorization code for AOAT
    AuthorizationResponse response = AuthorizationResponse.builder()
        .authorizationCode(code)
        .state(state)
        .build();
    
    AgentOperationAuthToken aoat = executor.exchangeAgentAuthToken(response);
    
    // Store AOAT for later use
    session.setAttribute("aoat", aoat.getJwtString());
    
    return ResponseEntity.ok("Authorization successful");
}
```

---

### Step 5: Build Authorization Context

**Method**: `AgentAuthorizationContext buildAuthContext(PrepareAuthorizationContextRequest contextRequest)`

**Purpose**: Generates the authorization context (WIT, WPT, AOAT) for tool execution.

**Parameters**:
- `workloadContext`: The workload context from Step 3
- `aoat`: The Agent Operation Authorization Token from Step 4

**Returns**: `AgentAuthorizationContext` containing:
- `wit`: Workload Identity Token
- `wpt`: Workload Proof Token
- `aoat`: Agent Operation Authorization Token

**Example**:
```java
// Retrieve context from session
WorkloadContext workloadContext = session.getAttribute("workload_context");
String aoatString = session.getAttribute("aoat");

// Parse AOAT
SignedJWT signedJwt = SignedJWT.parse(aoatString);
AgentOperationAuthToken aoat = aoatParser.parse(signedJwt);

// Build authorization context
PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
    .workloadContext(workloadContext)
    .aoat(aoat)
    .build();

AgentAuthorizationContext authContext = executor.buildAuthContext(request);

// Use context for MCP protocol adapter
McpAuthContext mcpAuthContext = new McpAuthContext(
    authContext.getAoat(),
    authContext.getWit(),
    authContext.getWpt()
);

McpAuthContextHolder.setContext(mcpAuthContext);

// Execute tool call
ToolResult result = toolAdapterManager.callTool(serverName, toolName, arguments);

// Clear context after use
McpAuthContextHolder.clearContext();
```

---

### Step 6: Get Workload Context

**Method**: `WorkloadContext getWorkloadContext()`

**Purpose**: Returns the workload context for cleanup.

**Returns**: The workload context containing workload identity and key pair information

**Example**:
```java
WorkloadContext workloadContext = executor.getWorkloadContext();
```

---

### Step 7: Cleanup Resources

**Method**: `void cleanup(WorkloadContext workloadContext)`

**Purpose**: Cleans up the authorization context after operation completion.

**Cleanup Operations**:
- Revoke the workload identity
- Clear temporary key pairs
- Remove cached tokens
- Clear sensitive data from memory

**Example**:
```java
try {
    // Execute tool with authorization
    ToolResult result = executeToolWithAuth(context);
} finally {
    // Always cleanup, even on error
    WorkloadContext workloadContext = executor.getWorkloadContext();
    executor.cleanup(workloadContext);
    session.removeAttribute("aoat");
    session.removeAttribute("workload_context");
}
```

---

## 🎯 Complete Usage Example

### Spring Boot Controller Example

```java
@RestController
@RequestMapping("/api/authorization")
public class AuthorizationController {
    
    @Autowired
    private AgentAapExecutor executor;
    
    @Autowired
    private SessionManager sessionManager;
    
    /**
     * Step 1-3: Initiate authorization flow
     */
    @PostMapping("/initiate")
    public ResponseEntity<?> initiateAuthorization(
            @RequestParam String userId,
            @RequestParam String userOriginalInput,
            @RequestParam String operationType,
            @RequestParam String resourceId) {
        
        try {
            // Step 1: Initiate user authentication
            InitiateAuthorizationRequest authRequest = InitiateAuthorizationRequest.builder()
                .redirectUri("https://example.com/callback")
                .state(generateRandomState())
                .build();
            
            String authUrl = executor.initiateUserAuth(authRequest);
            
            // Step 2: Exchange authorization code for ID Token
            // (This would happen in a separate callback endpoint)
            
            // Step 3: Request authorization URL
            WorkloadRequestContext workloadContext = WorkloadRequestContext.builder()
                .operationType(operationType)
                .resourceId(resourceId)
                .metadata(Map.of("userId", userId))
                .build();
            
            RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
                .userIdentityToken(idToken) // Assume ID Token is available
                .userOriginalInput(userOriginalInput)
                .workloadContext(workloadContext)
                .sessionId(session.getId())
                .build();
            
            RequestAuthUrlResponse response = executor.requestAuthUrl(request);
            
            // Store state and workload context
            sessionManager.setAttribute(session, "oauth_state", response.getState());
            sessionManager.setAttribute(session, "workload_context", response.getWorkloadContext());
            
            return ResponseEntity.ok(Map.of(
                "authorizationUrl", response.getAuthorizationUrl(),
                "state", response.getState()
            ));
            
        } catch (Exception e) {
            log.error("Failed to initiate authorization", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Failed to initiate authorization: " + e.getMessage());
        }
    }
    
    /**
     * Step 4: Handle authorization callback
     */
    @GetMapping("/callback")
    public ResponseEntity<?> handleCallback(
            @RequestParam("code") String code,
            @RequestParam("state") String state) {
        
        HttpSession session = getCurrentSession();
        
        try {
            // Validate state
            String storedState = sessionManager.getAttribute(session, "oauth_state");
            if (!state.equals(storedState)) {
                throw new IllegalStateException("Invalid state parameter");
            }
            
            // Step 4: Exchange authorization code for AOAT
            AuthorizationResponse response = AuthorizationResponse.builder()
                .authorizationCode(code)
                .state(state)
                .build();
            
            AgentOperationAuthToken aoat = executor.exchangeAgentAuthToken(response);
            
            // Store AOAT for later use
            sessionManager.setAttribute(session, "aoat", aoat.getJwtString());
            
            return ResponseEntity.ok("Authorization successful");
            
        } catch (Exception e) {
            log.error("Failed to handle callback", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Failed to handle callback: " + e.getMessage());
        }
    }
    
    /**
     * Step 5-7: Execute tool with authorization
     */
    @PostMapping("/execute")
    public ResponseEntity<?> executeTool(
            @RequestParam String serverName,
            @RequestParam String toolName,
            @RequestBody Map<String, Object> arguments) {
        
        HttpSession session = getCurrentSession();
        
        try {
            // Retrieve context from session
            WorkloadContext workloadContext = sessionManager.getAttribute(session, "workload_context");
            String aoatString = sessionManager.getAttribute(session, "aoat");
            
            if (workloadContext == null || aoatString == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Authorization context not found. Please authorize first.");
            }
            
            // Parse AOAT
            SignedJWT signedJwt = SignedJWT.parse(aoatString);
            AgentOperationAuthToken aoat = aoatParser.parse(signedJwt);
            
            // Step 5: Build authorization context
            PrepareAuthorizationContextRequest request = PrepareAuthorizationContextRequest.builder()
                .workloadContext(workloadContext)
                .aoat(aoat)
                .build();
            
            AgentAuthorizationContext authContext = executor.buildAuthContext(request);
            
            // Use context for MCP protocol adapter
            McpAuthContext mcpAuthContext = new McpAuthContext(
                authContext.getAoat(),
                authContext.getWit(),
                authContext.getWpt()
            );
            
            McpAuthContextHolder.setContext(mcpAuthContext);
            
            // Execute tool call
            ToolResult result = toolAdapterManager.callTool(serverName, toolName, arguments);
            
            // Clear context after use
            McpAuthContextHolder.clearContext();
            
            // Step 7: Cleanup resources
            executor.cleanup(workloadContext);
            sessionManager.removeAttribute(session, "aoat");
            sessionManager.removeAttribute(session, "workload_context");
            
            if (result.isSuccess()) {
                return ResponseEntity.ok(result.getData());
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(result.getError());
            }
            
        } catch (Exception e) {
            log.error("Failed to execute tool", e);
            
            // Cleanup on error
            try {
                WorkloadContext workloadContext = sessionManager.getAttribute(session, "workload_context");
                if (workloadContext != null) {
                    executor.cleanup(workloadContext);
                }
            } catch (Exception cleanupError) {
                log.error("Failed to cleanup resources", cleanupError);
            }
            
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Failed to execute tool: " + e.getMessage());
        }
    }
    
    private String generateRandomState() {
        return UUID.randomUUID().toString();
    }
    
    private HttpSession getCurrentSession() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        return attributes.getRequest().getSession(true);
    }
}
```

---

## 🔄 Workflow State Management

The executor manages state internally, allowing method chaining:

```java
// Method chaining example
AgentOperationAuthToken aoat = executor
    .exchangeUserIdToken(exchangeRequest)
    .requestAuthUrl(authUrlRequest)
    .exchangeAgentAuthToken(authResponse);
```

However, it's recommended to store intermediate results in session for web applications:

```java
// Store intermediate results in session
session.setAttribute("executor", executor);
session.setAttribute("workload_context", workloadContext);
session.setAttribute("aoat", aoat);

// Retrieve later
AgentAapExecutor executor = session.getAttribute("executor");
WorkloadContext workloadContext = session.getAttribute("workload_context");
AgentOperationAuthToken aoat = session.getAttribute("aoat");
```

---

## 📊 Error Handling

### Common Exceptions

| Exception | Cause | Solution |
|-----------|-------|----------|
| `WorkloadCreationException` | Failed to create workload | Check ID Token validity and Agent IDP availability |
| `FrameworkAuthorizationException` | Authorization failed | Check OAuth configuration and Authorization Server availability |
| `FrameworkTokenGenerationException` | Token generation failed | Check key configuration and token service availability |
| `FrameworkValidationException` | Validation failed | Check input parameters and request format |

### Error Handling Best Practices

```java
try {
    RequestAuthUrlResponse response = executor.requestAuthUrl(request);
} catch (WorkloadCreationException e) {
    log.error("Failed to create workload", e);
    throw new AuthorizationException("Unable to create workload: " + e.getMessage(), e);
} catch (FrameworkAuthorizationException e) {
    log.error("Authorization failed", e);
    throw new AuthorizationException("Authorization failed: " + e.getMessage(), e);
} catch (Exception e) {
    log.error("Unexpected error", e);
    throw new AuthorizationException("Unexpected error: " + e.getMessage(), e);
}
```

---

## 🔒 Security Considerations

### 1. Always Validate State Parameter

```java
String storedState = session.getAttribute("oauth_state");
if (!state.equals(storedState)) {
    throw new IllegalStateException("Invalid state parameter - possible CSRF attack");
}
```

### 2. Always Cleanup Resources

```java
try {
    // Execute operation
} finally {
    // Always cleanup
    executor.cleanup(workloadContext);
}
```

### 3. Never Store Sensitive Data in Logs

```java
// Bad
log.info("AOAT: {}", aoatString);

// Good
log.info("AOAT received (length: {})", aoatString.length());
```

### 4. Use HTTPS for All Authorization Requests

```java
// Always use HTTPS
String redirectUri = "https://example.com/callback";
```

---

## 📚 Best Practices

### 1. Use Builder Pattern for Requests

```java
// Good
RequestAuthUrlRequest request = RequestAuthUrlRequest.builder()
    .userIdentityToken(idToken)
    .userOriginalInput(userOriginalInput)
    .workloadContext(workloadContext)
    .sessionId(sessionId)
    .build();

// Bad - constructor is less readable
RequestAuthUrlRequest request = new RequestAuthUrlRequest(idToken, userOriginalInput, workloadContext, sessionId);
```

### 2. Always Handle Cleanup in Finally Block

```java
try {
    // Execute operation
} finally {
    // Always cleanup
    executor.cleanup(workloadContext);
}
```

### 3. Validate Input Parameters

```java
public ResponseEntity<?> initiateAuthorization(@RequestParam String userId) {
    if (userId == null || userId.trim().isEmpty()) {
        return ResponseEntity.badRequest().body("User ID is required");
    }
    
    // Continue with authorization
}
```

### 4. Log Security Events

```java
log.info("Authorization initiated for user: {}", userId);
log.info("Authorization callback received with state: {}", state);
log.info("Tool executed with authorization: server={}, tool={}", serverName, toolName);
```

---

## 🔗 Related Documentation

- [Framework Layer Overview](00-api-overview.md)
- [Actor Interfaces Guide](01-role-actor.md)
- [Spring Boot Controllers Guide](03-spring-boot-starter.md)
- [User Guide](../guide/start/00-user-guide.md)
- [Configuration Guide](../guide/configuration/)

---

**Version**: 0.1.0-beta.1-SNAPSHOT  
**Last Updated**: 2026-02-08
