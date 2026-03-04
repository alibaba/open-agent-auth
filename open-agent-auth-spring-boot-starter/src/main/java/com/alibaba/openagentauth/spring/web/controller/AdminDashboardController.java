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

import com.alibaba.openagentauth.core.audit.api.AuditService;
import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.protocol.wimse.workload.store.WorkloadRegistry;
import com.alibaba.openagentauth.framework.actor.AgentIdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Admin Dashboard controller providing a unified navigation view.
 * <p>
 * This controller dynamically detects which capability beans are available
 * in the application context and builds a navigation menu accordingly.
 * The dashboard uses a left sidebar + right content area layout, where
 * each admin sub-page is loaded in an iframe for seamless navigation.
 * </p>
 * <p>
 * The navigation items are determined at runtime based on the available beans:
 * </p>
 * <ul>
 *   <li>{@link BindingInstanceStore} → Binding Instances management</li>
 *   <li>{@link PolicyRegistry} → Policy Registry management</li>
 *   <li>{@link AuditService} → Audit Events viewer</li>
 *   <li>{@link AgentIdentityProvider} or {@link WorkloadRegistry} → Workload Identity management</li>
 * </ul>
 *
 * @since 1.0
 */
@Controller
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class AdminDashboardController {

    private static final Logger logger = LoggerFactory.getLogger(AdminDashboardController.class);

    private final Optional<BindingInstanceStore> bindingInstanceStore;
    private final Optional<PolicyRegistry> policyRegistry;
    private final Optional<AuditService> auditService;
    private final Optional<AgentIdentityProvider> agentIdentityProvider;
    private final Optional<WorkloadRegistry> workloadRegistry;

    /**
     * Creates a new AdminDashboardController with optional capability beans.
     *
     * @param bindingInstanceStore  the binding instance store (optional)
     * @param policyRegistry        the policy registry (optional)
     * @param auditService          the audit service (optional)
     * @param agentIdentityProvider the agent identity provider (optional)
     * @param workloadRegistry      the workload registry (optional)
     */
    public AdminDashboardController(
            Optional<BindingInstanceStore> bindingInstanceStore,
            Optional<PolicyRegistry> policyRegistry,
            Optional<AuditService> auditService,
            Optional<AgentIdentityProvider> agentIdentityProvider,
            Optional<WorkloadRegistry> workloadRegistry) {
        this.bindingInstanceStore = bindingInstanceStore;
        this.policyRegistry = policyRegistry;
        this.auditService = auditService;
        this.agentIdentityProvider = agentIdentityProvider;
        this.workloadRegistry = workloadRegistry;
        logger.info("AdminDashboardController initialized - admin dashboard is available at /admin");
    }

    /**
     * Renders the admin dashboard with dynamically detected navigation items.
     *
     * @param model the Spring MVC model
     * @return the dashboard view name
     */
    @GetMapping("${open-agent-auth.admin.endpoints.dashboard:/admin}")
    public String dashboardPage(Model model) {
        List<NavItem> navItems = buildNavigationItems();
        model.addAttribute("navItems", navItems);

        String defaultPage = navItems.isEmpty() ? "" : navItems.get(0).getUrl();
        model.addAttribute("defaultPage", defaultPage);

        return "admin/dashboard";
    }

    private List<NavItem> buildNavigationItems() {
        List<NavItem> items = new ArrayList<>();

        bindingInstanceStore.ifPresent(store ->
                items.add(new NavItem("bindings", "Binding Instances", "bi-link-45deg", "/admin/bindings")));

        policyRegistry.ifPresent(registry ->
                items.add(new NavItem("policies", "Policy Registry", "bi-shield-check", "/admin/policies")));

        auditService.ifPresent(service ->
                items.add(new NavItem("audit", "Audit Events", "bi-journal-text", "/admin/audit")));

        if (agentIdentityProvider.isPresent() || workloadRegistry.isPresent()) {
            items.add(new NavItem("workloads", "Workload Identity", "bi-cpu", "/admin/workloads"));
        }

        return items;
    }

    /**
     * Navigation item DTO for the dashboard sidebar.
     */
    public static class NavItem {
        private final String id;
        private final String label;
        private final String icon;
        private final String url;

        public NavItem(String id, String label, String icon, String url) {
            this.id = id;
            this.label = label;
            this.icon = icon;
            this.url = url;
        }

        public String getId() {
            return id;
        }

        public String getLabel() {
            return label;
        }

        public String getIcon() {
            return icon;
        }

        public String getUrl() {
            return url;
        }
    }
}
