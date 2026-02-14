## Agent Operation Authorization Token

### Purpose and Authority

The Agent Operation Authorization Token (also called Agent OA Token) represents the culmination of the authorization flow: the user's explicit consent to the agent's proposed operation. It serves as a cryptographically signed "authorization letter" that grants the agent permission to perform the requested operation, with all necessary claims for enforcement and auditability.

Unlike traditional OAuth access tokens, which typically contain only scopes and basic claims, the Agent OA Token contains a rich set of claims that enable fine-grained authorization and complete auditability. It includes the user's identity, the verified agent identity, a reference to the policy that governs the operation, the evidence credential capturing the user's original intent, and a semantic audit trail documenting the authorization decision.

The token is issued by the Authorization Server after successful validation of the PAR-JWT, identity binding verification, and user consent. The Authorization Server acts as the witness of the user's consent, presenting the rendered operation to the user on an AS-controlled interface and, upon explicit approval, issuing the token with embedded audit information. This audit information is covered by the AS's signature on the token, making it verifiable evidence of the consent event.

### Token Structure

The Agent OA Token contains both standard JWT claims and custom claims specific to the Agent Operation Authorization framework.

```json
{
  "iss": "https://as.example.com",
  "sub": "user_12345",
  "aud": ["https://api.example.com"],
  "exp": 1731668100,
  "iat": 1731664500,
  "jti": "aoat-789xyz",
  
  "scope": "agent:operation",
  
  "evidence": {
    "source_prompt_credential": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
  },
  
  "agent_identity": {
    "version": "1.0",
    "id": "urn:uuid:agent-identity-789",
    "issuer": "https://as.example.com",
    "issuedTo": "user_12345",
    "issuedFor": {
      "platform": "personal-agent.example.com",
      "client": "mobile-app-v1",
      "clientInstance": "dfp_abc123"
    },
    "issuanceDate": "2025-11-11T10:35:30Z",
    "validFrom": "2025-11-11T10:35:30Z",
    "expires": "2025-11-11T23:59:00Z"
  },
  
  "agent_operation_authorization": {
    "policy_id": "opa-policy-789"
  },
  
  "context": {
    "renderedText": "Purchase items under $50 during the Nov 11 promotion (valid until 23:59)"
  },
  
  "audit_trail": {
    "originalPromptText": "Buy something cheap on Nov 11 night",
    "renderedOperationText": "Purchase items under $50 during the Nov 11 promotion (valid until 23:59)",
    "semanticExpansionLevel": "medium",
    "userAcknowledgeTimestamp": "2025-11-11T10:33:00Z",
    "consentInterfaceVersion": "consent-ui-v2.1"
  },
  
  "references": {
    "relatedProposalId": "urn:uuid:op-proposal-456"
  },
  
  "delegation_chain": [
    {
      "delegator_jti": "urn:uuid:token-abc-123",
      "delegator_agent_identity": { "version": "1.0", "id": "urn:uuid:agent-identity-456", "issuer": "https://as.example.com", "issuedTo": "user_12345", "issuedFor": { "platform": "personal-agent.example.com", "client": "mobile-app-v1", "clientInstance": "dfp_abc123" }, "issuanceDate": "2025-11-11T10:35:30Z", "validFrom": "2025-11-11T10:35:30Z", "expires": "2025-11-11T23:59:00Z" },
      "delegation_timestamp": "2025-12-18T10:15:00Z",
      "operation_summary": "Delegate inventory check for item X",
      "as_signature": "eyJhbGciOiJSUzI1NiIs..."
    }
  ]
}
```

The `agent_identity` claim is issued by the Authorization Server after validating the user-workload binding through the WorkloadRegistry. It provides authoritative confirmation that the binding has been verified and is cryptographically endorsed by the AS. This enables Resource Servers to trust the identity binding without needing to re-validate the original ID Token and WIT.

The `agent_operation_authorization` claim contains a `policy_id` that references a registered OPA policy. The Resource Server retrieves this policy and evaluates it against the request context to make fine-grained authorization decisions. This policy-based approach enables complex, context-aware authorization that can consider factors such as the user's role, the resource's sensitivity, the time of day, and the data being accessed.

The `audit_trail` claim provides a complete semantic audit trail from the user's original intent to the system's final executed action. It includes the original prompt text, the rendered operation text, the semantic expansion level, the user acknowledgment timestamp, and the consent interface version. This information enables post-hoc analysis and compliance reporting.

The `delegation_chain` claim, when present, provides a complete history of agent-to-agent delegations, enabling Resource Servers to validate that the current agent's authority is derived without escalation from an original human-confirmed authorization. Each entry in the chain is signed by the Authorization Server, ensuring its integrity and non-repudiation.

### Token Issuance Process

The issuance of the Agent OA Token is a multi-step process that ensures cryptographic verification of all components and explicit user consent. When the user approves the authorization request, the Authorization Server retrieves the stored PAR-JWT and validates its signature and expiration. It extracts and validates the evidence credential, verifying its signature and ensuring it has not expired.

The Authorization Server validates the identity binding by verifying that the workload ID (WIT.sub) is registered in the WorkloadRegistry with the user's subject identifier from the ID Token. This cross-validation ensures that the workload requesting authorization is indeed bound to the authenticated user. The Authorization Server then registers the OPA policy referenced in the `agent_operation_proposal` claim, ensuring that the policy is available to all Resource Servers that will validate the token.

The Authorization Server constructs the Agent OA Token with all required claims, including the user identity, verified agent identity, policy reference, audit trail, and evidence credential. It signs the token with its private key and returns it to the agent as the access token for the authorized operation.

### Delegation Support

The framework supports agent-to-agent delegation, enabling primary agents to delegate subsets of their authorized operations to secondary agents while preserving end-to-end auditability and preventing privilege escalation. The delegation is managed by the Authorization Server, which acts as the central policy enforcer and trust anchor.

When an agent wants to delegate an operation, it submits a PAR request to the Authorization Server containing its current Agent OA Token, a new `agent_user_binding_proposal` for the secondary agent, and a descriptor of the requested sub-operation. The Authorization Server validates that the original token is valid and permits delegation, verifies that the requested sub-operation is strictly narrower than the original authorization, and authenticates the secondary agent's identity.

If all checks pass, the Authorization Server issues a new Agent OA Token for the secondary agent. The new token references the same original human intent, includes a new `agent_identity` for the secondary agent, and extends the `delegation_chain` with a new, AS-signed record referencing the delegating agent's token. Resource Servers can validate the entire delegation chain by verifying the AS signature on each entry and ensuring that no operation exceeds the cumulative scope of the chain.

---

