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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

/**
 * Audit configuration properties for the Open Agent Auth root configuration.
 * <p>
 * Controls audit logging functionality for tracking security events,
 * user actions, agent operations, and system activities.
 * </p>
 * <p>
 * <b>Note:</b> This class is distinct from
 * {@link com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.AuditProperties},
 * which is the Audit <em>capability</em> configuration. This class represents the root-level
 * audit configuration under {@code open-agent-auth.audit}.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   audit:
 *     enabled: false
 *     provider: logging
 * </pre>
 *
 * @since 1.0
 */
public class OpenAgentAuthAuditProperties {

    /**
     * Whether audit logging is enabled.
     * <p>
     * When enabled, the application will log security-relevant events
     * such as authentication, authorization, and data access operations.
     * </p>
     */
    private boolean enabled = false;

    /**
     * Audit provider implementation.
     * <p>
     * Specifies the provider implementation for audit logging.
     * Supported values include "logging" for file-based logging.
     * </p>
     */
    private String provider = "logging";

    /**
     * Gets whether audit logging is enabled.
     *
     * @return whether audit logging is enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether audit logging is enabled.
     *
     * @param enabled whether to enable audit logging
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the audit provider implementation.
     *
     * @return the audit provider name (e.g., "logging")
     */
    public String getProvider() {
        return provider;
    }

    /**
     * Sets the audit provider implementation.
     *
     * @param provider the audit provider name (e.g., "logging")
     */
    public void setProvider(String provider) {
        this.provider = provider;
    }
}
