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

import com.alibaba.openagentauth.framework.model.audit.AuditLogEntry;
import com.alibaba.openagentauth.framework.model.request.ResourceRequest;
import com.alibaba.openagentauth.framework.model.validation.ValidationResult;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkValidationException;
import com.alibaba.openagentauth.framework.oauth2.FrameworkOAuth2TokenServer;
import com.alibaba.openagentauth.framework.role.ApplicationRole;

/**
 * Resource Server actor interface.
 * <p>
 * This interface defines the contract for Resource Server actor implementations, which
 * host protected resources and implement the five-layer verification architecture.
 * The Resource Server actor is an independent entity responsible for validating all
 * aspects of incoming requests and enforcing access control policies.
 * </p>
 *
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>Layer 1: Workload Authentication:</b> Validate WIT signature and claims</li>
 *   <li><b>Layer 2: Request Integrity:</b> Validate WPT signature and integrity</li>
 *   <li><b>Layer 3: User Authentication:</b> Validate AOAT signature and claims</li>
 *   <li><b>Layer 4: Identity Consistency:</b> Verify user-workload identity binding</li>
 *   <li><b>Layer 5: Policy Evaluation:</b> Evaluate OPA policies for authorization</li>
 *   <li><b>Audit Logging:</b> Record all access attempts and decisions</li>
 * </ul>
 *
 * <h3>Design Principles:</h3>
 * <ul>
 *   <li><b>Actor Model:</b> Independent entity with encapsulated state</li>
 *   <li><b>Layered Security:</b> Each layer provides independent validation</li>
 *   <li><b>Defense in Depth:</b> Multiple security mechanisms</li>
 *   <li><b>Zero Trust:</b> All requests are fully validated</li>
 * </ul>
 *
 * <h3>Complete Workflow:</h3>
 *
 * <h4>Workflow 1: Five-Layer Verification</h4>
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │              Workflow 1: Five-Layer Verification Architecture               │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 *    ┌──────────────┐         ┌─────────────────┐           ┌────────────────┐      ┌──────────────────┐     ┌──────────────────┐
 *    │ MCP Client   │         │ Resource Server │           │  Agent IDP     │      │  Authz Server    │     │      OPA         │
 *    └──────┬───────┘         └──────┬──────────┘           └───────┬────────┘      └────────┬─────────┘     └────────┬─────────┘
 *           │                        │                              │                        │                        │
 *           │ 1. validateRequest(request)                           │                        │                        │
 *           │───────────────────────>│                              │                        │                        │
 *           │                        │                              │                        │                        │
 *           │                        │ 2. Layer 1: Validate WIT     │                        │                        │
 *           │                        │   - Get Public Key           │                        │                        │
 *           │                        │─────────────────────────────>│                        │                        │
 *           │                        │                              │                        │                        │
 *           │                        │ 3. Return Public Key         │                        │                        │
 *           │                        │<─────────────────────────────│                        │                        │
 *           │                        │                              │                        │                        │
 *           │                        │ 4. Verify WIT Signature      │                        │                        │
 *           │                        │   - Validate Claims          │                        │                        │
 *           │                        │   - Check Expiration         │                        │                        │
 *           │                        │                              │                        │                        │
 *           │                        │ 5. Layer 2: Validate WPT     │                        │                        │
 *           │                        │   - Verify Request Signature │                        │                        │
 *           │                        │   - Check Integrity          │                        │                        │
 *           │                        │                              │                        │                        │
 *           │                        │ 6. Layer 3: Validate AOAT    │                        │                        │
 *           │                        │   - Get Public Key           │                        │                        │
 *           │                        │──────────────────────────────────────────────────────>│                        │
 *           │                        │                              │                        │                        │
 *           │                        │ 7. Return Public Key         │                        │                        │
 *           │                        │<──────────────────────────────────────────────────────│                        │
 *           │                        │                              │                        │                        │
 *           │                        │ 8. Verify AOAT Signature     │                        │                        │
 *           │                        │   - Extract User ID          │                        │                        │
 *           │                        │   - Extract Policy ID        │                        │                        │
 *           │                        │                              │                        │                        │
 *           │                        │ 9. Layer 4: Verify Identity Consistency               │                        │
 *           │                        │   (user_id == workload.user) │                        │                        │
 *           │                        │                              │                        │                        │
 *           │                        │ 10. Layer 5: Evaluate Policy │                        │                        │
 *           │                        │───────────────────────────────────────────────────────────────────────────────>│
 *           │                        │                              │                        │                        │
 *           │                        │ 11. Return Allow/Deny        │                        │                        │
 *           │                        │<───────────────────────────────────────────────────────────────────────────────│
 *           │                        │                              │                        │                        │
 *           │ 12. Return ValidationResult                           │                        │                        │
 *           │<───────────────────────│                              │                        │                        │
 * </pre>
 *
 * <h4>Workflow 2: Audit Logging</h4>
 * <pre>
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                   Workflow 2: Audit Logging                                 │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 *    ┌──────────────┐         ┌─────────────────┐          ┌────────────────┐
 *    │ MCP Client   │         │ Resource Server │          │  Audit Store   │
 *    └──────┬───────┘         └──────┬──────────┘          └───────┬────────┘
 *           │                        │                             │
 *           │ 1. logAccess(auditLog) │                             │
 *           │───────────────────────>│                             │
 *           │                        │                             │
 *           │                        │ 2. Create Audit Entry       │
 *           │                        │   - Timestamp               │
 *           │                        │   - User ID                 │
 *           │                        │   - Workload ID             │
 *           │                        │   - Operation Type          │
 *           │                        │   - Resource ID             │
 *           │                        │   - Decision (Allow/Deny)   │
 *           │                        │   - Reason                  │
 *           │                        │                             │
 *           │                        │ 3. Store Audit Entry        │
 *           │                        │────────────────────────────>│
 *           │                        │                             │
 *           │                        │ 4. Return Confirmation      │
 *           │                        │<────────────────────────────│
 *           │                        │                             │
 *           │ 5. Acknowledge         │                             │
 *           │<───────────────────────│                             │
 * </pre>
 *
 * <h3>System Interactions:</h3>
 *
 * <h4>Workflow 1: Five-Layer Verification</h4>
 * <ul>
 *   <li><b>1:</b> MCP Client calls validateRequest() with resource request containing WIT, WPT, AOAT</li>
 *   <li><b>2:</b> Resource Server retrieves Agent IDP public key from JWKS endpoint</li>
 *   <li><b>3:</b> Agent IDP returns public key for WIT signature verification</li>
 *   <li><b>4:</b> Resource Server verifies WIT signature and validates all claims (iss, sub, exp, aud, cnf)</li>
 *   <li><b>5:</b> Resource Server validates WPT signature using public key from WIT's cnf claim</li>
 *   <li><b>6:</b> Resource Server retrieves Authorization Server public key for AOAT verification</li>
 *   <li><b>7:</b> Authorization Server returns public key</li>
 *   <li><b>8:</b> Resource Server verifies AOAT signature and extracts user ID and policy ID</li>
 *   <li><b>9:</b> Resource Server verifies identity consistency: AOAT.sub == WIT.agent_identity.issuedTo</li>
 *   <li><b>10:</b> Resource Server evaluates OPA policy with request context (user, workload, operation, resource)</li>
 *   <li><b>11:</b> OPA returns authorization decision (allow/deny)</li>
 *   <li><b>12:</b> Resource Server returns ValidationResult with all layer results and final decision</li>
 * </ul>
 *
 * <h4>Workflow 2: Audit Logging</h4>
 * <ul>
 *   <li><b>1:</b> Resource Server calls logAccess() with audit log entry</li>
 *   <li><b>2:</b> Resource Server creates audit entry with complete access information</li>
 *   <li><b>3:</b> Audit Store stores the audit entry for compliance and forensic analysis</li>
 *   <li><b>4:</b> Audit Store confirms storage</li>
 *   <li><b>5:</b> Resource Server acknowledges audit logging completion</li>
 * </ul>
 *
 * @see ApplicationRole#RESOURCE_SERVER
 * @see FrameworkOAuth2TokenServer
 * @since 1.0
 */
public interface ResourceServer {

    /**
     * Validates an incoming request using the five-layer verification architecture.
     * <p>
     * This method performs all five layers of validation in sequence:
     * <ol>
     *   <li>Layer 1: Validate WIT (Workload Identity Token) - signature and claims</li>
     *   <li>Layer 2: Validate WPT (Workload Proof Token) - request integrity</li>
     *   <li>Layer 3: Validate AOAT (Agent Operation Authorization Token) - signature and claims</li>
     *   <li>Layer 4: Verify identity consistency between user and workload</li>
     *   <li>Layer 5: Evaluate authorization policy using OPA</li>
     * </ol>
     * </p>
     * <p>
     * If any layer validation fails, the method returns a ValidationResult with
     * valid=false and details about the failure. All layers must pass for the
     * request to be considered valid.
     * </p>
     *
     * @param request the incoming request to validate, containing WIT, WPT, AOAT, and context
     * @return the validation result with detailed information for each layer
     * @throws FrameworkValidationException if validation fails at any layer
     */
    ValidationResult validateRequest(ResourceRequest request) throws FrameworkValidationException;

    /**
     * Logs access attempt for audit purposes.
     * <p>
     * This method records the access attempt, including request details,
     * validation results, and authorization decision. Audit logs are essential
     * for security compliance and forensic analysis.
     * </p>
     *
     * @param auditLog the audit log entry containing timestamp, user ID, workload ID,
     *                 operation type, resource ID, decision, and reason
     */
    void logAccess(AuditLogEntry auditLog);

}