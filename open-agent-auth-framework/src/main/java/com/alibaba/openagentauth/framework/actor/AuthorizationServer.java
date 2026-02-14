/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alibaba.openagentauth.framework.actor;

import com.alibaba.openagentauth.framework.exception.auth.FrameworkAuthorizationException;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkParProcessingException;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;
import com.alibaba.openagentauth.framework.model.request.AoatIssuanceRequest;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenClient;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenServer;
import com.alibaba.openagentauth.framework.role.ApplicationRole;
import com.alibaba.openagentauth.core.protocol.oauth2.dcr.model.DcrResponse;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.model.oauth2.par.ParResponse;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
// AuthorizationResponse is no longer needed as processAuthorization is removed

import java.util.List;

/**
 * Authorization Server actor interface.
 * <p>
 * This interface defines the contract for Authorization Server actor implementations, which
 * handle authorization requests, manage user authorization, and issue Agent Operation
 * Authorization Tokens (AOAT). The Authorization Server actor is an independent entity
 * responsible for validating workload identities, registering OPA policies, and making
 * authorization decisions.
 * </p>
 * 
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>Authorization Request Processing:</b> Handle PAR requests and OAuth 2.0 authorization flow</li>
 *   <li><b>Identity Verification:</b> Validate WIT and user identity tokens</li>
 *   <li><b>Identity Consistency Check:</b> Verify workload-user identity binding</li>
 *   <li><b>Policy Registration:</b> Register OPA policies for authorization</li>
 *   <li><b>Token Issuance:</b> Generate Agent Operation Authorization Tokens</li>
 *   <li><b>Audit Logging:</b> Record all authorization decisions</li>
 * </ul>
 * 
 * <h3>Design Principles:</h3>
 * <ul>
 *   <li><b>Actor Model:</b> Independent entity with encapsulated state</li>
 *   <li><b>Zero Trust:</b> All requests are verified and authorized</li>
 *   <li><b>Identity Consistency:</b> Strong binding between workload and user identities</li>
 *   <li><b>Layered Security:</b> Multiple validation layers</li>
 * </ul>
 * 
 * <h3>Complete Workflow:</h3>
 * 
 * <h4>Workflow 1: OAuth Client Registration (DCR)</h4>
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │              Workflow 1: OAuth Client Registration (DCR)                    │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 *    ┌──────────────────┐     ┌────────────────────┐       ┌────────────────┐      ┌──────────────────┐
 *    │ AOA Bridge Actor │     │ Authz Server Actor │       │  Agent IDP     │      │  JWKS Endpoint   │
 *    └──────┬───────────┘     └──────┬─────────────┘       └───────┬────────┘      └────────┬─────────┘
 *           │                        │                             │                        │
 *           │ 1. registerOAuthClient(WIT, redirectUris)            │                        │
 *           │───────────────────────>│                             │                        │
 *           │                        │                             │                        │
 *           │                        │ 2. Validate WIT Signature   │                        │
 *           │                        │─────────────────────────────────────────────────────>│
 *           │                        │                             │                        │
 *           │                        │ 3. Return Public Key        │                        │
 *           │                        │<─────────────────────────────────────────────────────│
 *           │                        │                             │                        │
 *           │                        │ 4. Verify WIT Claims        │                        │
 *           │                        │   - Signature               │                        │
 *           │                        │   - Expiration (exp)        │                        │
 *           │                        │   - Issuer (iss)            │                        │
 *           │                        │   - Audience (aud)          │                        │
 *           │                        │                             │                        │
 *           │                        │ 5. Extract Workload ID      │                        │
 *           │                        │   (WIT.sub)                 │                        │
 *           │                        │                             │                        │
 *           │                        │ 6. Register OAuth Client    │                        │
 *           │                        │   - client_id = WIT.sub     │                        │
 *           │                        │   - auth_method = private_key_jwt                    │
 *           │                        │                             │                        │
 *           │ 7. Return DcrResponse  │                             │                        │
 *           │<───────────────────────│                             │                        │
 * </pre>
 * 
 * <h4>Workflow 2: PAR Processing & Authorization</h4>
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │           Workflow 2: PAR Processing & Authorization Flow                   │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 *    ┌──────────────────┐     ┌────────────────────┐        ┌────────────────┐      ┌──────────────────┐
 *    │ AOA Bridge Actor │     │ Authz Server Actor │        │  AS User IDP   │      │      OPA         │
 *    └──────┬───────────┘     └──────┬─────────────┘        └───────┬────────┘      └────────┬─────────┘
 *           │                        │                              │                        │
 *           │ 1. processParRequest(parRequest)                      │                        │
 *           │───────────────────────>│                              │                        │
 *           │                        │                              │                        │
 *           │                        │ 2. Validate PAR-JWT          │                        │
 *           │                        │   - Signature                │                        │
 *           │                        │   - Claims (WIT, user ID)    │                        │
 *           │                        │   - Prompt VC                │                        │
 *           │                        │                              │                        │
 *           │ 3. Return ParResponse  │                              │                        │
 *           │<───────────────────────│                              │                        │
 *           │   (request_uri)        │                              │                        │
 *           │                        │                              │                        │
 *           │ 4. Redirect User       │                              │                        │
 *           │───────────────────────>│                              │                        │
 *           │   to /authorize        │                              │                        │
 *           │                        │                              │                        │
 *           │                        │ 5. Authenticate User         │                        │
 *           │                        │─────────────────────────────>│                        │
 *           │                        │                              │                        │
 *           │                        │ 6. Return User ID Token      │                        │
 *           │                        │<─────────────────────────────│                        │
 *           │                        │                              │                        │
 *           │                        │ 7. Validate Identity Consistency                      │
 *           │                        │   (user_id == workload.user) │                        │
 *           │                        │                              │                        │
 *           │                        │ 8. Register OPA Policy       │                        │
 *           │                        │──────────────────────────────────────────────────────>│
 *           │                        │                              │                        │
 *           │                        │ 9. Return Policy ID          │                        │
 *           │                        │<──────────────────────────────────────────────────────│
 *           │                        │                              │                        │
 *           │ 10. issueAoat(request) │                              │                        │
 *           │<───────────────────────│                              │                        │
 *</pre>
 * 
 * <h4>Workflow 3: Policy Registration (during Authorization)</h4>
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │          Workflow 3: Policy Registration (during Authorization Flow)        │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 *    ┌──────────────────┐     ┌────────────────────┐         ┌────────────────┐
 *    │ Authz Server     │     │ Authz Server Actor │         │      OPA       │
 *    └──────┬───────────┘     └──────┬─────────────┘         └───────┬────────┘
 *           │                        │                               │
 *           │ 1. Convert Operation Proposal to Rego Policy           │
 *           │───────────────────────>│                               │
 *           │                        │                               │
 *           │                        │ 2. Validate Rego Syntax       │
 *           │                        │                               │
 *           │                        │ 3. Register with OPA          │
 *           │                        │──────────────────────────────>│
 *           │                        │                               │
 *           │                        │ 4. Return Policy ID           │
 *           │                        │<──────────────────────────────│
 *           │                        │                               │
 *           │ 5. Use Policy ID in Agent OA Token                     │
 *           │<───────────────────────│                               │
 *</pre>
 * 
 * <h4>Workflow 4: Policy Evaluation (at Resource Server)</h4>
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │          Workflow 4: Policy Evaluation (at Resource Server - Layer 4)       │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 *    ┌──────────────────┐     ┌───────────────────────┐         ┌────────────────┐
 *    │ Resource Server  │     │ Resource Server Actor │         │      OPA       │
 *    └──────┬───────────┘     └──────┬────────────────┘         └───────┬────────┘
 *           │                        │                                  │
 *           │ 1. Extract policy_id from Agent OA Token                  │
 *           │───────────────────────>│                                  │
 *           │                        │                                  │
 *           │                        │ 2. Build Authorization Context   │
 *           │                        │   - user_id                      │
 *           │                        │   - workload_id                  │
 *           │                        │   - resource_id                  │
 *           │                        │   - operation                    │
 *           │                        │                                  │
 *           │                        │ 3. Evaluate against OPA          │
 *           │                        │─────────────────────────────────>│
 *           │                        │                                  │
 *           │                        │ 4. Return Decision               │
 *           │                        │<─────────────────────────────────│
 *           │                        │                                  │
 *           │ 5. Allow or Deny Resource Access                          │
 *           │<───────────────────────│                                  │
 *</pre>
 * 
 * <h3>System Interactions:</h3>
 * 
 * <h4>Workflow 1: OAuth Client Registration (DCR)</h4>
 * <ul>
 *   <li><b>1:</b> AOA Bridge calls registerOAuthClient() with WIT and redirect URIs</li>
 *   <li><b>2:</b> Authorization Server retrieves Agent IDP's public key from JWKS endpoint</li>
 *   <li><b>3:</b> JWKS endpoint returns the public key for WIT signature verification</li>
 *   <li><b>4:</b> Authorization Server verifies WIT signature and claims (exp, iss, aud)</li>
 *   <li><b>5:</b> Authorization Server extracts workload ID from WIT.sub claim</li>
 *   <li><b>6:</b> Authorization Server registers OAuth Client with client_id = WIT.sub</li>
 *   <li><b>7:</b> Authorization Server returns DcrResponse with client_id and registration metadata</li>
 * </ul>
 * 
 * <h4>Workflow 2: PAR Processing & Authorization</h4>
 * <ul>
 *   <li><b>1:</b> AOA Bridge calls processParRequest() with PAR request containing WIT and user ID</li>
 *   <li><b>2:</b> Authorization Server validates PAR-JWT signature and claims (WIT, user ID, Prompt VC)</li>
 *   <li><b>3:</b> Authorization Server returns ParResponse with request_uri for authorization endpoint</li>
 *   <li><b>4:</b> AOA Bridge redirects user to authorization endpoint with request_uri</li>
 *   <li><b>5:</b> Authorization Server authenticates user with AS User IDP</li>
 *   <li><b>6:</b> AS User IDP returns user ID Token</li>
 *   <li><b>7:</b> Authorization Server validates identity consistency (user_id == workload.user)</li>
 *   <li><b>8:</b> Authorization Server registers OPA policy for operation authorization</li>
 *   <li><b>9:</b> OPA returns policy ID</li>
 *   <li><b>10:</b> Authorization Server calls issueAoat() and returns Agent OA Token</li>
 * </ul>
 * 
 * <h4>Workflow 3: Policy Registration (during Authorization)</h4>
 * <ul>
 *   <li><b>1:</b> Authorization Server converts operation proposal to Rego policy</li>
 *   <li><b>2:</b> Authorization Server validates Rego policy syntax</li>
 *   <li><b>3:</b> Authorization Server registers policy with OPA engine</li>
 *   <li><b>4:</b> OPA returns policy ID</li>
 *   <li><b>5:</b> Authorization Server embeds policy_id in Agent OA Token</li>
 * </ul>
 * 
 * <h4>Workflow 4: Policy Evaluation (at Resource Server)</h4>
 * <ul>
 *   <li><b>1:</b> Resource Server extracts policy_id from Agent OA Token</li>
 *   <li><b>2:</b> Resource Server builds authorization context (user_id, workload_id, resource_id, operation)</li>
 *   <li><b>3:</b> Resource Server evaluates request against OPA policy</li>
 *   <li><b>4:</b> OPA returns authorization decision (allow/deny)</li>
 *   <li><b>5:</b> Resource Server allows or denies resource access based on decision</li>
 * </ul>
 * 
 * <h3>Usage Example:</h3>
 * <pre>{@code
 * // Step 1: Register OAuth Client using DCR
 * String wit = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ...";
 * List<String> redirectUris = List.of("https://client.example.com/callback");
 * 
 * DcrResponse dcrResponse = authzServerActor.registerOAuthClient(wit, redirectUris);
 * String clientId = dcrResponse.getClientId();
 * 
 * // Step 2: Process PAR Request
 * ParRequest parRequest = new ParRequest.Builder()
 *     .clientId(clientId)
 *     .wit(wit)
 *     .userId("user-123")
 *     .promptVc(promptVc)
 *     .operationProposal(operationProposal)
 *     .build();
 * 
 * ParResponse parResponse = authzServerActor.processParRequest(parRequest);
 * String requestUri = parResponse.getRequestUri();
 * 
 * // Step 3: Process Authorization (after user consents)
 * String authorizationCode = "auth-code-xyz";
 * AuthorizationResponse authResponse = authzServerActor.processAuthorization(authorizationCode);
 * 
 * // Step 4: Issue Agent OA Token
 * AoatIssuanceRequest aoatRequest = new AoatIssuanceRequest.Builder()
 *     .userId("user-123")
 *     .workloadId("workload-456")
 *     .operationAuthorization(operationAuth)
 *     .evidence(evidence)
 *     .auditTrail(auditTrail)
 *     .policyId("policy-789")
 *     .build();
 * 
 * AgentOperationAuthToken aoat = authzServerActor.issueAoat(aoatRequest);
 * String aoatString = aoat.getJwtString();
 * 
 * // Step 5: Register and Evaluate Policy
 * String policyId = "shopping-policy";
 * String regoPolicy = "package auth\\nallow { input.user == input.resource.owner }";
 * 
 * PolicyRegistrationResponse policyResponse = authzServerActor.registerPolicy(policyId, regoPolicy);
 * 
 * AuthorizationContext context = new AuthorizationContext.Builder()
 *     .userId("user-123")
 *     .resourceId("resource-abc")
 *     .operation("read")
 *     .build();
 * 
 * PolicyEvaluationResult evalResult = authzServerActor.evaluatePolicy(policyId, context);
 * if (evalResult.isAllowed()) {
 *     // Operation is authorized
 * }
 * }</pre>
 * 
 * <h3>Trust Chain Establishment Points:</h3>
 * <ul>
 *   <li><b>Trust Chain Point 4:</b> OAuth WIMSE Client Registration (registerOAuthClient)</li>
 *   <li><b>Trust Chain Point 5:</b> Prompt VC Verification (processParRequest)</li>
 *   <li><b>Trust Chain Point 6:</b> WIT Signature Validation (validateWit)</li>
 *   <li><b>Trust Chain Point 7:</b> Identity Consistency Verification (validateIdentityConsistency)</li>
 * </ul>
 * 
 * @see ApplicationRole#AUTHORIZATION_SERVER
 * @see FrameworkOAuth2TokenClient
 * @see FrameworkOAuth2TokenServer
 * @see AgentOperationAuthToken
 * @see DcrResponse
 * @see WorkloadIdentityToken
 * @since 1.0
 */
public interface AuthorizationServer extends FrameworkOAuth2TokenClient, FrameworkOAuth2TokenServer {
    
    /**
     * Processes a Pushed Authorization Request (PAR).
     * <p>
     * This method handles PAR requests as defined in RFC 9126, validating the
     * request JWT, workload identity, and user identity. It returns a request URI
     * that can be used in the authorization endpoint.
     * </p>
     *
     * @param parRequest the PAR request
     * @return the PAR response containing the request URI
     * @throws FrameworkParProcessingException if PAR processing fails
     */
    ParResponse processParRequest(ParRequest parRequest) throws FrameworkParProcessingException;
    
    /**
     * Issues an Agent Operation Authorization Token.
     * <p>
     * This method generates an AOAT containing user identity, workload identity,
     * operation authorization, evidence, and audit trail information.
     * Internally, this method validates identity consistency and registers
     * OPA policies for the authorization decision.
     * </p>
     *
     * @param request the token issuance request
     * @return the issued Agent Operation Authorization Token
     * @throws FrameworkTokenGenerationException if token generation fails
     */
    AgentOperationAuthToken issueAoat(AoatIssuanceRequest request) throws FrameworkTokenGenerationException;
    
    /**
     * Registers an OAuth client using Dynamic Client Registration (DCR).
     * <p>
     * This method handles OAuth 2.0 Dynamic Client Registration (RFC 7591) using the
     * workload's WIT as the client assertion. The WIT's subject (WIT.sub) becomes the
     * OAuth client_id, and the authentication method is set to private_key_jwt.
     * </p>
     * 
     * <p>
     * This step establishes the mapping between the workload identity and OAuth client
     * identity, which is required before submitting PAR requests. The Authorization Server
     * validates the WIT signature and returns client registration information.
     * Internally, this method validates the WIT signature and claims.
     * </p>
     *
     * <p>
     * <b>Trust Chain Establishment Point 4:</b> This is the OAuth WIMSE Client Registration
     * trust chain point. The Authorization Server:
     * <ol>
     *   <li>Validates the WIT signature using the Agent IDP's JWKS endpoint</li>
     *   <li>Verifies WIT claims (expiration, issuer, audience)</li>
     *   <li>Ensures WIT is issued by a trusted WIMSE IDP</li>
     *   <li>Registers OAuth Client without client_secret</li>
     *   <li>Establishes workload identity (WIT.sub) to OAuth client identity (client_id) mapping</li>
     * </ol>
     * </p>
     *
     * @param clientAssertion the JWT client assertion containing the WIT
     * @param redirectUris the redirect URIs for the client
     * @return the DCR response containing client_id and registration metadata
     * @throws FrameworkAuthorizationException if client registration fails
     * @throws IllegalArgumentException if parameters are null or invalid
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591">RFC 7591 - OAuth 2.0 Dynamic Client Registration</a>
     */
    DcrResponse registerOAuthClient(String clientAssertion, List<String> redirectUris) throws FrameworkAuthorizationException;

}