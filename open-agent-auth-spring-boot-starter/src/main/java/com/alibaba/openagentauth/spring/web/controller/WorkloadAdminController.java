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

import com.alibaba.openagentauth.core.protocol.wimse.workload.store.WorkloadRegistry;
import com.alibaba.openagentauth.framework.actor.AgentIdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Optional;

/**
 * Admin UI controller for Workload Identity management.
 * <p>
 * Provides a web-based management interface for viewing workload identities,
 * issuing Workload Identity Tokens (WIT), and revoking workloads.
 * This controller is enabled when either {@link AgentIdentityProvider} (Agent IDP role,
 * full read-write access) or {@link WorkloadRegistry} (Agent role, read-only access)
 * is available in the application context.
 * </p>
 *
 * @see AgentIdentityProvider
 * @see WorkloadRegistry
 * @see WorkloadController
 * @since 1.0
 */
@Controller
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "open-agent-auth.admin", name = "enabled", havingValue = "true")
@ConditionalOnBean({WorkloadRegistry.class})
public class WorkloadAdminController {

    private static final Logger logger = LoggerFactory.getLogger(WorkloadAdminController.class);

    private final boolean readOnly;

    /**
     * Creates a new WorkloadAdminController.
     * <p>
     * When AgentIdentityProvider is present (Agent IDP role), the page operates in
     * full read-write mode. When only WorkloadRegistry is present (Agent role with
     * RemoteWorkloadRegistry), the page operates in read-only mode.
     * </p>
     *
     * @param agentIdentityProvider the agent identity provider (optional)
     */
    public WorkloadAdminController(Optional<AgentIdentityProvider> agentIdentityProvider) {
        this.readOnly = agentIdentityProvider.isEmpty();
        String mode = readOnly ? "read-only" : "read-write";
        logger.info("WorkloadAdminController initialized in {} mode - workload management UI is available at /admin/workloads", mode);
    }

    @GetMapping("${open-agent-auth.admin.endpoints.workloads:/admin/workloads}")
    public String workloadsPage(Model model) {
        model.addAttribute("readOnly", readOnly);
        return "admin/workloads";
    }
}
