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

import com.alibaba.openagentauth.core.binding.BindingInstance;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.model.identity.AgentIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST API controller for Binding Instance operations.
 * <p>
 * This controller exposes the BindingInstanceStore functionality via RESTful endpoints,
 * enabling distributed binding management across multiple services.
 * Resource Servers can query binding instances from the Authorization Server through these APIs
 * to perform two-layer identity verification (user identity + workload identity).
 * </p>
 * <p>
 * <b>Endpoints:</b></p>
 * <ul>
 *   <li>GET /api/v1/bindings/{bindingInstanceId} - Get a binding instance by ID</li>
 *   <li>POST /api/v1/bindings - Create a new binding instance</li>
 *   <li>DELETE /api/v1/bindings/{bindingInstanceId} - Delete a binding instance</li>
 * </ul>
 *
 * @see BindingInstanceStore
 * @see BindingInstance
 * @since 1.0
 */
@RestController
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(BindingInstanceStore.class)
public class BindingInstanceController {

    private static final Logger logger = LoggerFactory.getLogger(BindingInstanceController.class);

    private final BindingInstanceStore bindingInstanceStore;

    /**
     * Creates a new BindingInstanceController.
     *
     * @param bindingInstanceStore the binding instance store
     */
    public BindingInstanceController(BindingInstanceStore bindingInstanceStore) {
        this.bindingInstanceStore = bindingInstanceStore;
        logger.info("BindingInstanceController initialized");
    }

    /**
     * Retrieves a binding instance by its ID.
     *
     * @param bindingInstanceId the binding instance ID
     * @return the binding instance if found
     */
    @GetMapping("${open-agent-auth.capabilities.operation-authorization.endpoints.binding.get:/api/v1/bindings/{bindingInstanceId}}")
    public ResponseEntity<BindingInstance> getBinding(@PathVariable String bindingInstanceId) {
        logger.debug("Getting binding instance with ID: {}", bindingInstanceId);

        if (ValidationUtils.isNullOrEmpty(bindingInstanceId)) {
            logger.warn("Binding instance ID is null or empty");
            return ResponseEntity.badRequest().build();
        }

        BindingInstance binding = bindingInstanceStore.retrieve(bindingInstanceId);
        if (binding == null) {
            logger.warn("Binding instance not found: {}", bindingInstanceId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        return ResponseEntity.ok(binding);
    }

    /**
     * Creates a new binding instance.
     *
     * @param request the binding instance creation request
     * @return the created binding instance
     */
    @PostMapping("${open-agent-auth.capabilities.operation-authorization.endpoints.binding.registry:/api/v1/bindings}")
    public ResponseEntity<BindingInstance> createBinding(@RequestBody BindingInstanceRequest request) {
        logger.debug("Creating new binding instance for user: {}, workload: {}", 
                     request.getUserIdentity(), request.getWorkloadIdentity());

        try {
            BindingInstance binding = BindingInstance.builder()
                    .bindingInstanceId(request.getBindingInstanceId())
                    .userIdentity(request.getUserIdentity())
                    .workloadIdentity(request.getWorkloadIdentity())
                    .agentIdentity(request.getAgentIdentity())
                    .createdAt(request.getCreatedAt())
                    .expiresAt(request.getExpiresAt())
                    .build();

            bindingInstanceStore.store(binding);
            return ResponseEntity.status(HttpStatus.CREATED).body(binding);
        } catch (Exception e) {
            logger.error("Failed to create binding instance", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Deletes a binding instance by its ID.
     *
     * @param bindingInstanceId the binding instance ID
     * @return 204 No Content if successful
     */
    @DeleteMapping("${open-agent-auth.capabilities.operation-authorization.endpoints.binding.delete:/api/v1/bindings/{bindingInstanceId}}")
    public ResponseEntity<Void> deleteBinding(@PathVariable String bindingInstanceId) {
        logger.debug("Deleting binding instance with ID: {}", bindingInstanceId);

        if (ValidationUtils.isNullOrEmpty(bindingInstanceId)) {
            logger.warn("Binding instance ID is null or empty");
            return ResponseEntity.badRequest().build();
        }

        if (!bindingInstanceStore.exists(bindingInstanceId)) {
            logger.warn("Binding instance not found for deletion: {}", bindingInstanceId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        bindingInstanceStore.delete(bindingInstanceId);
        return ResponseEntity.noContent().build();
    }

    /**
     * Request DTO for binding instance creation.
     */
    public static class BindingInstanceRequest {
        private String bindingInstanceId;
        private String userIdentity;
        private String workloadIdentity;
        private AgentIdentity agentIdentity;
        private java.time.Instant createdAt;
        private java.time.Instant expiresAt;

        public String getBindingInstanceId() {
            return bindingInstanceId;
        }

        public void setBindingInstanceId(String bindingInstanceId) {
            this.bindingInstanceId = bindingInstanceId;
        }

        public String getUserIdentity() {
            return userIdentity;
        }

        public void setUserIdentity(String userIdentity) {
            this.userIdentity = userIdentity;
        }

        public String getWorkloadIdentity() {
            return workloadIdentity;
        }

        public void setWorkloadIdentity(String workloadIdentity) {
            this.workloadIdentity = workloadIdentity;
        }

        public AgentIdentity getAgentIdentity() {
            return agentIdentity;
        }

        public void setAgentIdentity(AgentIdentity agentIdentity) {
            this.agentIdentity = agentIdentity;
        }

        public java.time.Instant getCreatedAt() {
            return createdAt;
        }

        public void setCreatedAt(java.time.Instant createdAt) {
            this.createdAt = createdAt;
        }

        public java.time.Instant getExpiresAt() {
            return expiresAt;
        }

        public void setExpiresAt(java.time.Instant expiresAt) {
            this.expiresAt = expiresAt;
        }
    }
}