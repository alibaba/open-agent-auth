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

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.AgentRequestContext;
import com.alibaba.openagentauth.framework.role.ApplicationRole;

/**
 * Agent Identity Provider actor interface.
 * <p>
 * This interface defines the contract for Agent IDP actor implementations, which extend
 * the standard WIMSE Workload IDP capabilities with agent-specific functionality. The Agent IDP
 * actor is an independent entity that manages agent workload identities and issues
 * Workload Identity Tokens (WIT) for agent operations.
 * </p>
 *
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>Agent Workload Management:</b> Creates and manages virtual workloads for agent operations</li>
 *   <li><b>WIT Issuance:</b> Issues Workload Identity Tokens for agent operations</li>
 *   <li><b>Identity Binding:</b> Binds agent identity to user identity for traceability</li>
 *   <li><b>Agent Lifecycle:</b> Manages the lifecycle of agent workloads</li>
 * </ul>
 *
 * <h3>Design Principles:</h3>
 * <ul>
 *   <li><b>Interface Segregation:</b> Separates agent-specific concerns from standard WIT concerns</li>
 *   <li><b>Open-Closed Principle:</b> Extends WIT capabilities without modifying WIT interface</li>
 *   <li><b>Actor Model:</b> Independent entity with encapsulated state and behavior</li>
 * </ul>
 *
 *
 *
 * <h3>Complete Workflow:</h3>
 *
 * <h4>Workflow 1: Agent Workload Creation</h4>
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │              Workflow 1: Agent Workload Creation & Identity Binding         │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 *    ┌──────────────┐         ┌─────────────────┐          ┌────────────────┐      ┌──────────────────┐
 *    │ Agent Actor  │         │ Agent IDP Actor │          │ Agent User IDP │      │  Workload Store  │
 *    └──────┬───────┘         └──────┬──────────┘          └───────┬────────┘      └────────┬─────────┘
 *           │                        │                             │                        │
 *           │ 1. createAgentWorkload(idToken, context)             │                        │
 *           │───────────────────────>│                             │                        │
 *           │                        │                             │                        │
 *           │                        │ 2. Validate ID Token        │                        │
 *           │                        │────────────────────────────>│                        │
 *           │                        │                             │                        │
 *           │                        │ 3. Return Validation Result │                        │
 *           │                        │<────────────────────────────│                        │
 *           │                        │                             │                        │
 *           │                        │ 4. Extract User ID (sub)    │                        │
 *           │                        │                             │                        │
 *           │                        │ 5. Generate Key Pair        │                        │
 *           │                        │                             │                        │
 *           │                        │ 6. Create Workload Entry    │                        │
 *           │                        │─────────────────────────────────────────────────────>│
 *           │                        │                             │                        │
 *           │                        │ 7. Store Workload           │                        │
 *           │                        │<─────────────────────────────────────────────────────│
 *           │                        │                             │                        │
 *           │ 8. Return WorkloadInfo │                             │                        │
 *           │<───────────────────────│                             │                        │
 * </pre>
 *
 * <h4>Workflow 2: WIT Issuance</h4>
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                 Workflow 2: WIT Issuance                                   │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 *    ┌─────────────┐       ┌─────────────────┐          ┌──────────────────┐       ┌──────────────────┐
 *    │ Agent Actor │       │ Agent IDP Actor │          │  Workload Store  │       │  Key Management  │
 *    └──────┬──────┘       └──────┬──────────┘          └──────────┬───────┘       └────────┬─────────┘
 *           │                     │                                │                        │
 *           │ 1. issueWit(workloadId)                              │                        │
 *           │────────────────────>│                                │                        │
 *           │                     │                                │                        │
 *           │                     │ 2. Retrieve Workload           │                        │
 *           │                     │───────────────────────────────>│                        │
 *           │                     │                                │                        │
 *           │                     │ 3. Return Workload Info        │                        │
 *           │                     │<───────────────────────────────│                        │
 *           │                     │                                │                        │
 *           │                     │ 4. Generate WIT Claims        │                        │
 *           │                     │                                │                        │
 *           │                     │ 5. Sign WIT                    │                        │
 *           │                     │────────────────────────────────────────────────────────>│
 *           │                     │                                │                        │
 *           │                     │ 6. Return Signed WIT           │                        │
 *           │                     │<────────────────────────────────────────────────────────│
 *           │                     │                                │                        │
 *           │ 7. Return WIT       │                                │                        │
 *           │<────────────────────│                                │                        │
 * </pre>
 *
 * <h3>System Interactions:</h3>
 *
 * <h4>Workflow 1: Agent Workload Creation</h4>
 * <ul>
 *   <li><b>1:</b> Agent Actor calls createAgentWorkload() with ID Token and request context</li>
 *   <li><b>2:</b> Agent IDP validates ID Token signature and claims with Agent User IDP</li>
 *   <li><b>3:</b> Agent User IDP returns validation result (valid/invalid)</li>
 *   <li><b>4:</b> Agent IDP extracts user ID from validated ID Token's sub claim</li>
 *   <li><b>5:</b> Agent IDP generates temporary key pair for the workload</li>
 *   <li><b>6:</b> Agent IDP creates workload entry with user binding</li>
 *   <li><b>7:</b> Workload Store stores the workload metadata</li>
 *   <li><b>8:</b> Agent IDP returns WorkloadInfo containing workload ID and public key</li>
 * </ul>
 *
 * <h4>Workflow 2: WIT Issuance</h4>
 * <ul>
 *   <li><b>1:</b> Agent Actor calls issueWit() with workload ID</li>
 *   <li><b>2:</b> Agent IDP retrieves workload information from Workload Store</li>
 *   <li><b>3:</b> Workload Store returns workload info including user binding and public key</li>
 *   <li><b>4:</b> Agent IDP generates WIT claims</li>
 *   <li><b>5:</b> Agent IDP signs WIT using its private key</li>
 *   <li><b>6:</b> Key Management returns signed WIT</li>
 *   <li><b>7:</b> Agent IDP returns WorkloadIdentityToken to Agent Actor</li>
 * </ul>
 *
 * <h3>Usage Example:</h3>
 * <pre>{@code
 * // Step 1: Create Agent Workload
 * String idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAifQ...";
 * AgentRequestContext context = new AgentRequestContext(
 *     "query_products",
 *     "shopping",
 *     Map.of("platform", "web", "client", "smart-assistant")
 * );
 *
 * WorkloadInfo workloadInfo = agentIdpActor.createAgentWorkload(idToken, context);
 * String workloadId = workloadInfo.getWorkloadId();
 * PublicKey publicKey = workloadInfo.getPublicKey();
 *
 * // Step 2: Issue WIT
 * WorkloadIdentityToken wit = agentIdpActor.issueWit(workloadId);
 *
 * // Step 3: Use WIT for authorization
 * String witString = wit.getJwtString();
 * // Submit WIT to Authorization Server for OAuth client registration
 *
 * // Step 4: Cleanup (after operation completes)
 * agentIdpActor.revokeAgentWorkload(workloadId);
 * }</pre>
 *
 * <h3>WIT Structure:</h3>
 * <pre>
 * {
 *   "iss": "wimse://example.com",
 *   "sub": "agent-instance-123",
 *   "exp": 1704067200,
 *   "jti": "wit-abc123",
 *   "cnf": {
 *     "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
 *   }
 * }
 * </pre>
 *
 * @see ApplicationRole#AGENT_IDP
 * @see WorkloadIdentityToken
 * @since 1.0
 */
public interface AgentIdentityProvider {

    /**
     * Creates an agent workload for the specified user.
     * <p>
     * This method creates a virtual workload specifically for agent operations,
     * binding it to the user identity for traceability. The workload includes
     * a temporary key pair for token issuance and request signing.
     * </p>
     *
     * <p>
     * The agent workload is designed to be short-lived and isolated, ensuring
     * that each agent operation has its own secure context.
     * </p>
     *
     * <p>
     * This method validates the ID Token's signature and validity before creating
     * the workload, ensuring that only authenticated users can create workloads.
     * The user identifier is extracted from the validated ID Token's sub claim.
     * </p>
     *
     * @param idToken the user identity token (ID Token) issued by Agent User IDP.
     *                The ID Token must be signed by a trusted Agent User IDP and
     *                contain a valid sub claim. The IDP will verify the signature,
     *                expiration, issuer, and audience before extracting the user identity.
     * @param context the agent request context containing operation type, resource info, etc.
     * @return the agent workload information including the generated key pair
     * @throws WorkloadCreationException if workload creation fails
     * @throws IllegalArgumentException if parameters are null or invalid
     */
    WorkloadInfo createAgentWorkload(String idToken, AgentRequestContext context) throws WorkloadCreationException;

    /**
     * Issues a Workload Identity Token (WIT).
     * <p>
     * This method creates a WIT for the specified workload.
     * </p>
     *
     * @param agentWorkloadId the agent workload identifier (must exist and be valid)
     * @return the Workload Identity Token (WIT)
     * @throws FrameworkTokenGenerationException if token generation fails
     * @throws WorkloadNotFoundException if the workload does not exist or has been revoked
     * @throws IllegalArgumentException if agentWorkloadId is null or invalid
     */
    WorkloadIdentityToken issueWit(String agentWorkloadId)
        throws FrameworkTokenGenerationException, WorkloadNotFoundException;

    /**
     * Issues a Workload Identity Token (WIT) using standard request model.
     * <p>
     * This is the standard-compliant implementation that accepts
     * {@link IssueWitRequest}
     * as defined in draft-liu-agent-operation-authorization.
     * </p>
     *
     * <h3>Workflow:</h3>
     * <ul>
     *   <li><b>Step 1:</b> Validate IssueWitRequest and extract core fields</li>
     *   <li><b>Step 2:</b> Validate ID Token and extract user identity</li>
     *   <li><b>Step 3:</b> Find an existing active workload for the same user + client binding</li>
     *   <li><b>Step 4:</b> If no valid workload exists, create a new one</li>
     *   <li><b>Step 5:</b> Issue a WIT with independent expiration time</li>
     * </ul>
     *
     * <h3>Core Fields:</h3>
     * <ul>
     *   <li><b>ID Token:</b> From {@code agentUserBindingProposal.userIdentityToken}</li>
     *   <li><b>Client ID:</b> From {@code context.agent.client}</li>
     *   <li><b>Public Key:</b> From {@code publicKey} (framework extension field)</li>
     * </ul>
     *
     * <h3>Note:</h3>
     * <p>
     * This method uses the standard request model as defined in 
     * draft-liu-agent-operation-authorization.
     * </p>
     *
     * @param request the standard IssueWitRequest
     * @return the Workload Identity Token (WIT)
     * @throws FrameworkTokenGenerationException if token generation fails
     * @throws WorkloadCreationException if workload creation fails
     * @throws IllegalArgumentException if request is null or invalid
     * @since 1.0
     */
    WorkloadIdentityToken issueWit(IssueWitRequest request)
        throws FrameworkTokenGenerationException, WorkloadCreationException;

    /**
     * Revokes an agent workload.
     * <p>
     * This method revokes the specified agent workload, invalidating any tokens
     * issued for it. This is useful for security incidents or when the agent
     * operation is completed.
     * </p>
     *
     * <p>
     * After revocation, any WIT issued for this workload should be
     * considered invalid by resource servers.
     * </p>
     *
     * @param agentWorkloadId the agent workload identifier
     * @throws WorkloadNotFoundException if the workload does not exist
     */
    void revokeAgentWorkload(String agentWorkloadId) throws WorkloadNotFoundException;

    /**
     * Gets agent workload information by ID.
     * <p>
     * This method retrieves information about a specific agent workload, including
     * its status, user binding, and expiration time.
     * </p>
     *
     * @param agentWorkloadId the agent workload identifier
     * @return the agent workload information
     * @throws WorkloadNotFoundException if workload is not found
     */
    WorkloadInfo getAgentWorkload(String agentWorkloadId) throws WorkloadNotFoundException;

}
