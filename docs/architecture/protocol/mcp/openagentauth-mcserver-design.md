## Tool Registration and Execution

### Tool Registration

The MCP protocol requires tools to be registered with the server before they can be invoked by agents. The OpenAgentAuthMcpServer supports tool registration through the standard MCP `tools/list` method, which returns a list of available tools with their metadata. This registration process is typically performed when the server starts up, but can also be dynamic, allowing tools to be added or removed at runtime.

Tool metadata includes the tool name, description, input schema, and output schema. The input schema defines the expected structure and types of input parameters, enabling validation and auto-completion in agent implementations. The output schema defines the structure of the return value, enabling agents to parse and process results correctly.

The OpenAgentAuthMcpServer does not modify the tool registration process, allowing existing MCP server implementations to continue using their standard registration mechanisms. However, the adapter can enhance tool metadata by adding security-related information such as required scopes, sensitivity levels, or policy identifiers. This information helps agents understand the security requirements of each tool and obtain appropriate authorization before invoking them.

### Tool Invocation Flow

The tool invocation flow begins when an agent sends a `tools/call` request to the MCP server. The request includes the tool name and input parameters that conform to the tool's input schema. The OpenAgentAuthMcpServer intercepts this request before it reaches the underlying tool implementation.

The interceptor first extracts the authentication credentials from the HTTP headers, validating that all required headers are present and properly formatted. It then constructs a ResourceRequest object containing the authentication tokens, HTTP method, URI, headers, and body. This object represents the complete context needed for authorization verification.

The interceptor calls the ResourceServer's validateRequest method with the ResourceRequest object. The ResourceServer performs the five-layer verification, checking the WIT signature and claims, verifying the WPT signature and request binding, validating the Agent OA Token signature and authorization, checking identity consistency between user and workload, and evaluating the OPA policy for the requested operation. This comprehensive verification ensures that every tool invocation is traceable back to explicit user consent through the semantic audit trail embedded in the tokens.

If any layer of verification fails, the ResourceServer returns a ValidationResult with isValid set to false and error messages describing the failure. The interceptor returns an error response to the agent, preventing tool execution. The error response includes details about which verification layer failed and why, enabling the agent to understand and potentially correct the issue.

If all verification layers pass, the ResourceServer returns a ValidationResult with isValid set to true, along with extracted identity and policy information. The interceptor allows the request to proceed to the underlying tool implementation, which executes the tool and returns the result. The interceptor also logs the successful tool invocation for audit purposes, recording the user identity, workload identity, tool name, input parameters, and execution result, enabling post-hoc analysis and compliance verification.

```plantuml
@startuml MCP Tool Invocation Flow
!theme plain
skinparam backgroundColor #FEFEFE
skinparam handwritten false
skinparam sequenceMessageAlign center

actor "AI Agent" as Agent
participant "OpenAgentAuthMcpServer" as Server
participant "McpAuthInterceptor" as Interceptor
participant "ResourceServer" as RS
participant "FiveLayerVerifier" as Verifier
participant "Tool Implementation" as Tool

Agent -> Server: tools/call request\n(Headers: Authorization, X-Workload-Identity, X-Workload-Proof)
activate Server

Server -> Interceptor: Intercept request
activate Interceptor

Interceptor -> Interceptor: Extract credentials\n- Agent OA Token\n- WIT\n- WPT

Interceptor -> Interceptor: Validate headers format
Interceptor -> Interceptor: Build ResourceRequest

Interceptor -> RS: validateRequest(ResourceRequest)
activate RS

RS -> Verifier: Verify WIT (Layer 1)
activate Verifier
Verifier -> Verifier: Verify signature\nCheck expiration\nExtract workload ID
Verifier --> RS: WIT valid
deactivate Verifier

RS -> Verifier: Verify WPT (Layer 2)
activate Verifier
Verifier -> Verifier: Verify signature\nCheck timestamp\nVerify request binding
Verifier --> RS: WPT valid
deactivate Verifier

RS -> Verifier: Verify Agent OA Token (Layer 3)
activate Verifier
Verifier -> Verifier: Verify signature\nCheck expiration\nExtract user ID
Verifier --> RS: Agent OA Token valid
deactivate Verifier

RS -> Verifier: Check identity consistency (Layer 4)
activate Verifier
Verifier -> Verifier: Verify:\nWIT.agent_identity.issuedTo ==\nAgent OA Token.sub\nWIT.sub == Agent OA Token.agent_identity.workloadId
Verifier --> RS: Identity consistent
deactivate Verifier

RS -> Verifier: Evaluate policy (Layer 4)
activate Verifier
Verifier -> Verifier: Retrieve policy\nConstruct evaluation context\nEvaluate Rego rules
Verifier --> RS: Policy result: allow
deactivate Verifier

RS --> Interceptor: ValidationResult(valid=true)
deactivate RS

Interceptor -> Interceptor: Log successful authorization
Interceptor -> Tool: Execute tool
activate Tool
Tool --> Interceptor: Tool result
deactivate Tool

Interceptor -> Interceptor: Log tool execution
Interceptor --> Server: Return tool result
deactivate Interceptor

Server --> Agent: tools/call response
deactivate Server

@enduml
```

