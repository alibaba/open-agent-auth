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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.CreateWorkloadRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.CreateWorkloadResponse;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.GetWorkloadRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWorkloadTokenRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitResponse;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.RevokeWorkloadRequest;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.WorkloadInfo;
import com.alibaba.openagentauth.framework.actor.AgentIdentityProvider;
import com.alibaba.openagentauth.framework.exception.token.FrameworkTokenGenerationException;
import com.alibaba.openagentauth.framework.model.response.WorkloadResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST Controller for Workload Identity (WIP).
 * <p>
 * This controller implements the Workload Identity Provider functionality according to the
 * WIMSE (Workload Identity and Management for Security) protocol specification. It provides
 * RESTful endpoints for workload lifecycle management and Workload Identity Token (WIT) issuance.
 * </p>
 * <p>
 * <b>Protocol Compliance:</b></p>
 * <p>
 * This controller follows the IETF WIMSE protocol draft standards:
 * </p>
 * <ul>
 *   <li>Workload identifiers are treated as opaque strings per WIMSE specification</li>
 *   <li>All operations use POST method with parameters in request body for security</li>
 *   <li>WIT issuance follows the standard token format and claims structure</li>
 *   <li>Workload lifecycle management adheres to WIMSE best practices</li>
 * </ul>
 * 
 * <b>API Endpoints:</b></p>
 * <ul>
 *   <li>POST /api/v1/workloads/token/issue - Issue WIT with automatic workload management</li>
 *   <li>POST /api/v1/workloads/revoke - Revoke a workload identity</li>
 *   <li>POST /api/v1/workloads/get - Retrieve workload information</li>
 * </ul>
 *
 * @see AgentIdentityProvider
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-creds">IETF WIMSE Workload Credentials Draft</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-wimse-protocol">IETF WIMSE Protocol Draft</a>
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(AgentIdentityProvider.class)
public class WorkloadController {

    private static final Logger logger = LoggerFactory.getLogger(WorkloadController.class);

    private final AgentIdentityProvider agentIdentityProvider;

    /**
     * Constructor for dependency injection.
     * <p>
     * Initializes the controller with the required AgentIdentityProvider service.
     * The provider handles the core WIMSE protocol operations including workload
     * creation, WIT issuance, and lifecycle management.
     * </p>
     *
     * @param agentIdentityProvider the workload identity provider service implementing WIMSE operations
     */
    public WorkloadController(
            AgentIdentityProvider agentIdentityProvider
    ) {
        this.agentIdentityProvider = agentIdentityProvider;
    }


    /**
     * Issues a WIT with automatic workload lifecycle management.
     * <p>
     * This convenience endpoint combines workload creation and WIT issuance into a single
     * atomic operation, optimizing for performance and reducing client complexity.
     * The automatic lifecycle management follows this strategy:
     * </p>
     <ul>
     *   <li>Finding an existing workload by workloadUniqueKey (userId:clientId)</li>
     *   <li>Reusing the workload if it exists and is not expired</li>
     *   <li>Creating a new workload if none exists or the existing one is expired</li>
     *   <li>Issuing a WIT for the workload</li>
     * </ul>
     * <p>
     * This endpoint reduces the number of HTTP calls from 2 to 1, improving performance
     * and simplifying the client-side code.
     * </p>
     *
     * @param request the standard IssueWitRequest containing context, proposal, and public key
     * @return the issued WIT with workload information
     */
    @PostMapping("${open-agent-auth.capabilities.workload-identity.endpoints.workload.issue:/api/v1/workloads/token/issue}")
    public ResponseEntity<IssueWitResponse> issue(
            @RequestBody IssueWitRequest request
    ) {
        logger.info("Issuing WIT with automatic workload management");
        
        try {
            // Use the standard method that handles workload lifecycle automatically
            WorkloadIdentityToken wit = agentIdentityProvider.issueWit(request);
            
            IssueWitResponse response = IssueWitResponse.builder()
                    .wit(wit.getJwtString())
                    .build();
            
            logger.info("Successfully issued WIT with automatic workload management");
            return ResponseEntity.ok(response);
            
        } catch (WorkloadCreationException e) {
            logger.error("Failed to create workload: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(IssueWitResponse.error(e.getMessage()));
        } catch (FrameworkTokenGenerationException e) {
            logger.error("Failed to issue WIT: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(IssueWitResponse.error(e.getMessage()));
        }
    }

    /**
     * Revokes a workload identity.
     * <p>
     * This endpoint revokes the specified agent workload, invalidating any tokens
     * issued for it. This is useful for security incidents or when the agent
     * operation is completed.
     * </p>
     * <p>
     * <b>Protocol Compliance:</b> This endpoint uses POST method with workloadId in the
     * request body, following WIMSE protocol recommendations for handling workload identifiers
     * as opaque strings that should not be exposed in URLs.
     * </p>
     *
     * @param request the request containing the workload identifier
     * @return success message
     */
    @PostMapping("${open-agent-auth.capabilities.workload-identity.endpoints.workload.revoke:/api/v1/workloads/revoke}")
    public ResponseEntity<Void> revoke(
            @RequestBody RevokeWorkloadRequest request
    ) {
        logger.info("Revoking workload: {}", request.getWorkloadId());
        
        try {
            agentIdentityProvider.revokeAgentWorkload(request.getWorkloadId());
            logger.info("Successfully revoked workload: {}", request.getWorkloadId());
            return ResponseEntity.noContent().build();
            
        } catch (WorkloadNotFoundException e) {
            logger.error("Workload not found: {}", request.getWorkloadId());
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Gets agent workload information by ID.
     * <p>
     * This endpoint retrieves information about a specific agent workload, including
     * its status, user binding, and expiration time.
     * </p>
     * <p>
     * <b>Protocol Compliance:</b> This endpoint uses POST method with workloadId in the
     * request body, following WIMSE protocol recommendations for handling workload identifiers
     * as opaque strings that should not be exposed in URLs.
     * </p>
     *
     * @param request the request containing the workload identifier
     * @return the workload information
     */
    @PostMapping("${open-agent-auth.capabilities.workload-identity.endpoints.workload.get:/api/v1/workloads/get}")
    public ResponseEntity<WorkloadResponse> get(
            @RequestBody GetWorkloadRequest request
    ) {
        logger.debug("Getting workload information: {}", request.getWorkloadId());
        
        try {
            WorkloadInfo workloadInfo = agentIdentityProvider.getAgentWorkload(request.getWorkloadId());
            
            WorkloadResponse response = WorkloadResponse.builder()
                    .workloadId(workloadInfo.getWorkloadId())
                    .userId(workloadInfo.getUserId())
                    .publicKey(workloadInfo.getPublicKey())
                    .createdAt(workloadInfo.getCreatedAt())
                    .expiresAt(workloadInfo.getExpiresAt())
                    .status(workloadInfo.getStatus())
                    .build();
            
            return ResponseEntity.ok(response);
            
        } catch (WorkloadNotFoundException e) {
            logger.error("Workload not found: {}", request.getWorkloadId());
            return ResponseEntity.notFound().build();
        }
    }
}