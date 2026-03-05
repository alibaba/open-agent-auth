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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Admin UI controller for Audit Event viewing.
 * <p>
 * Provides a web-based interface for viewing and searching audit trail events.
 * This controller is only enabled when {@link AuditService} is available in the
 * application context.
 * </p>
 *
 * @see AuditService
 * @see AuditController
 * @since 1.0
 */
@Controller
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "open-agent-auth.admin", name = "enabled", havingValue = "true")
@ConditionalOnBean(AuditService.class)
public class AuditAdminController {

    private static final Logger logger = LoggerFactory.getLogger(AuditAdminController.class);

    public AuditAdminController() {
        logger.info("AuditAdminController initialized - audit events UI is available at /admin/audit");
    }

    @GetMapping("${open-agent-auth.admin.endpoints.audit:/admin/audit}")
    public String auditPage() {
        return "admin/audit";
    }
}
