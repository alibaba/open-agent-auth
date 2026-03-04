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

import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Admin UI controller for Binding Instance management.
 * <p>
 * Provides a web-based management interface for viewing, creating, and deleting
 * binding instances. This controller is only enabled when {@link BindingInstanceStore}
 * is available in the application context.
 * </p>
 *
 * @see BindingInstanceStore
 * @see BindingInstanceController
 * @since 1.0
 */
@Controller
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnBean(BindingInstanceStore.class)
public class BindingInstanceAdminController {

    private static final Logger logger = LoggerFactory.getLogger(BindingInstanceAdminController.class);

    public BindingInstanceAdminController() {
        logger.info("BindingInstanceAdminController initialized - binding management UI is available at /admin/bindings");
    }

    @GetMapping("${open-agent-auth.admin.endpoints.bindings:/admin/bindings}")
    public String bindingsPage() {
        return "admin/bindings";
    }
}
