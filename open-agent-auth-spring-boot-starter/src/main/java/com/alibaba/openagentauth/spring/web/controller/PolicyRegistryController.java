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

import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyRegistration;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST API controller for Policy Registry operations.
 * <p>
 * This controller exposes the PolicyRegistry functionality via RESTful endpoints,
 * enabling distributed policy management across multiple services.
 * Resource Servers can query policies from the Authorization Server through these APIs.
 * </p>
 * <p>
 * <b>Endpoints:</b></p>
 * <ul>
 *   <li>GET /api/v1/policies/{policyId} - Get a policy by ID</li>
 *   <li>POST /api/v1/policies - Register a new policy</li>
 *   <li>DELETE /api/v1/policies/{policyId} - Delete a policy</li>
 * </ul>
 *
 * @see PolicyRegistry
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnExpression("'${open-agent-auth.roles.authorization-server.enabled:false}' == 'true'")
public class PolicyRegistryController {

    private static final Logger logger = LoggerFactory.getLogger(PolicyRegistryController.class);

    private final PolicyRegistry policyRegistry;

    /**
     * Creates a new PolicyRegistryController.
     *
     * @param policyRegistry the policy registry
     */
    public PolicyRegistryController(PolicyRegistry policyRegistry) {
        this.policyRegistry = policyRegistry;
        logger.info("PolicyRegistryController initialized");
    }

    /**
     * Retrieves a policy by its ID.
     *
     * @param policyId the policy ID
     * @return the policy if found
     */
    @GetMapping("${open-agent-auth.capabilities.operation-authorization.endpoints.policy.get:/api/v1/policies/{policyId}}")
    public ResponseEntity<Policy> getPolicy(@PathVariable String policyId) {
        logger.debug("Getting policy with ID: {}", policyId);

        try {
            Policy policy = policyRegistry.get(policyId);
            return ResponseEntity.ok(policy);
        } catch (PolicyNotFoundException e) {
            logger.warn("Policy not found: {}", policyId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    /**
     * Registers a new policy.
     *
     * @param request the policy registration request
     * @return the registered policy
     */
    @PostMapping("${open-agent-auth.capabilities.operation-authorization.endpoints.policy.registry:/api/v1/policies}")
    public ResponseEntity<PolicyRegistration> registerPolicy(@RequestBody PolicyRegistrationRequest request) {
        logger.debug("Registering new policy with description: {}", request.getDescription());

        try {
            PolicyRegistration registration = policyRegistry.register(
                    request.getRegoPolicy(),
                    request.getDescription(),
                    request.getCreatedBy(),
                    request.getExpirationTime()
            );

            return ResponseEntity.status(HttpStatus.CREATED).body(registration);
        } catch (Exception e) {
            logger.error("Failed to register policy", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Deletes a policy by its ID.
     *
     * @param policyId the policy ID
     * @return 204 No Content if successful
     */
    @DeleteMapping("${open-agent-auth.capabilities.operation-authorization.endpoints.policy.delete:/api/v1/policies/{policyId}}")
    public ResponseEntity<Void> deletePolicy(@PathVariable String policyId) {
        logger.debug("Deleting policy with ID: {}", policyId);

        try {
            policyRegistry.delete(policyId);
            return ResponseEntity.noContent().build();
        } catch (PolicyNotFoundException e) {
            logger.warn("Policy not found for deletion: {}", policyId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }

    /**
     * Request DTO for policy registration.
     */
    public static class PolicyRegistrationRequest {
        private String regoPolicy;
        private String description;
        private String createdBy;
        private java.time.Instant expirationTime;

        public String getRegoPolicy() {
            return regoPolicy;
        }

        public void setRegoPolicy(String regoPolicy) {
            this.regoPolicy = regoPolicy;
        }

        public String getDescription() {
            return description;
        }

        public void setDescription(String description) {
            this.description = description;
        }

        public String getCreatedBy() {
            return createdBy;
        }

        public void setCreatedBy(String createdBy) {
            this.createdBy = createdBy;
        }

        public java.time.Instant getExpirationTime() {
            return expirationTime;
        }

        public void setExpirationTime(java.time.Instant expirationTime) {
            this.expirationTime = expirationTime;
        }
    }
}
