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
package com.alibaba.openagentauth.spring.autoconfigure;

import com.alibaba.openagentauth.spring.autoconfigure.properties.OpenAgentAuthProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.RolesProperties;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.*;

/**
 * Configuration Validator (Layer 3).
 * <p>
 * This validator runs at application startup to verify the consistency of
 * role and capability configurations. It provides early detection of
 * misconfigurations and clear error messages to help developers fix issues.
 * </p>
 *
 * <h3>Design Rationale</h3>
 * <p>
 * Following the DRY principle (inspired by Spring Boot Actuator's endpoint management),
 * capabilities are configured once at the capability level via
 * {@code open-agent-auth.capabilities.xxx.enabled=true}. Roles do <b>not</b> declare
 * which capabilities they use — instead, this validator maintains a built-in mapping
 * ({@code ROLE_REQUIRED_CAPABILITIES}) that defines which capabilities each role requires.
 * This eliminates configuration redundancy and prevents user confusion.
 * </p>
 *
 * <h3>Validation Rules</h3>
 * <ul>
 *   <li><b>Required Capabilities</b>: Validates that each enabled role has its
 *       required capabilities also enabled</li>
 *   <li><b>Role Co-existence Warnings</b>: Detects when multiple roles are enabled
 *       simultaneously and warns about potential Bean conflicts</li>
 * </ul>
 *
 * <h3>Supported Role Co-existence Scenarios</h3>
 * <ul>
 *   <li><b>Agent User IDP + AS User IDP</b>: Fully supported — same IDP serving
 *       both Agent and Authorization Server user authentication</li>
 *   <li><b>Authorization Server + AS User IDP</b>: Fully supported — AS with
 *       embedded user authentication</li>
 *   <li><b>Agent + Agent IDP</b>: Supported — Agent acting as its own IDP</li>
 *   <li><b>Authorization Server + Resource Server</b>: Supported — combined
 *       deployment for small-scale scenarios</li>
 * </ul>
 *
 * @since 1.0
 */
@AutoConfiguration
@EnableConfigurationProperties({OpenAgentAuthProperties.class})
@ConditionalOnProperty(prefix = "open-agent-auth", name = "enabled", havingValue = "true")
public class ConfigurationValidator {

    private static final Logger logger = LoggerFactory.getLogger(ConfigurationValidator.class);

    private final OpenAgentAuthProperties properties;

    /**
     * Role-to-required-capabilities mapping.
     * Each role requires certain capabilities to be enabled for proper functioning.
     */
    private static final Map<String, List<String>> ROLE_REQUIRED_CAPABILITIES = new LinkedHashMap<>();

    static {
        ROLE_REQUIRED_CAPABILITIES.put(ROLE_AGENT_USER_IDP, List.of("oauth2-server", "user-authentication"));
        ROLE_REQUIRED_CAPABILITIES.put(ROLE_AS_USER_IDP, List.of("oauth2-server", "user-authentication"));
        ROLE_REQUIRED_CAPABILITIES.put(ROLE_AGENT, List.of("oauth2-client"));
        ROLE_REQUIRED_CAPABILITIES.put(ROLE_AUTHORIZATION_SERVER, List.of("oauth2-server"));
        ROLE_REQUIRED_CAPABILITIES.put(ROLE_AGENT_IDP, List.of("workload-identity"));
        ROLE_REQUIRED_CAPABILITIES.put(ROLE_RESOURCE_SERVER, List.of());
    }

    public ConfigurationValidator(OpenAgentAuthProperties properties) {
        this.properties = properties;
    }

    /**
     * Validates configuration consistency at startup.
     * <p>
     * This method runs after all beans are initialized and checks:
     * </p>
     * <ol>
     *   <li>Each enabled role has its required capabilities enabled</li>
     *   <li>Warns about role co-existence scenarios that may need attention</li>
     * </ol>
     */
    @PostConstruct
    public void validate() {
        if (properties.getRoles() == null || properties.getRoles().isEmpty()) {
            logger.debug("No roles configured, skipping validation");
            return;
        }

        List<String> enabledRoles = findEnabledRoles();
        if (enabledRoles.isEmpty()) {
            logger.debug("No roles enabled, skipping validation");
            return;
        }

        logger.info("Validating configuration for enabled roles: {}", enabledRoles);

        validateRequiredCapabilities(enabledRoles);
        detectRoleCoexistence(enabledRoles);
    }

    private List<String> findEnabledRoles() {
        List<String> enabledRoles = new ArrayList<>();
        for (Map.Entry<String, RolesProperties.RoleProperties> entry : properties.getRoles().entrySet()) {
            if (entry.getValue().isEnabled()) {
                enabledRoles.add(entry.getKey());
            }
        }
        return enabledRoles;
    }

    private void validateRequiredCapabilities(List<String> enabledRoles) {
        var capabilities = properties.getCapabilities();

        for (String roleName : enabledRoles) {
            List<String> requiredCapabilities = ROLE_REQUIRED_CAPABILITIES.getOrDefault(roleName, List.of());
            for (String capability : requiredCapabilities) {
                boolean capabilityEnabled = isCapabilityEnabled(capability, capabilities);
                if (!capabilityEnabled) {
                    logger.warn("Role '{}' requires capability '{}' to be enabled. "
                            + "Please set 'open-agent-auth.capabilities.{}.enabled=true' in your configuration.",
                            roleName, capability, capability);
                }
            }
        }
    }

    private boolean isCapabilityEnabled(String capabilityName, Object capabilities) {
        if (capabilities == null) {
            return false;
        }
        var caps = properties.getCapabilities();
        return switch (capabilityName) {
            case "oauth2-server" -> caps.getOAuth2Server() != null && caps.getOAuth2Server().isEnabled();
            case "oauth2-client" -> caps.getOAuth2Client() != null && caps.getOAuth2Client().isEnabled();
            case "user-authentication" -> caps.getUserAuthentication() != null && caps.getUserAuthentication().isEnabled();
            case "workload-identity" -> caps.getWorkloadIdentity() != null && caps.getWorkloadIdentity().isEnabled();
            case "operation-authorization" -> caps.getOperationAuthorization() != null && caps.getOperationAuthorization().isEnabled();
            case "audit" -> caps.getAudit() != null && caps.getAudit().isEnabled();
            default -> {
                logger.warn("Unknown capability: {}", capabilityName);
                yield false;
            }
        };
    }

    private void detectRoleCoexistence(List<String> enabledRoles) {
        if (enabledRoles.size() <= 1) {
            return;
        }

        logger.info("Multiple roles enabled: {}. Verifying co-existence compatibility.", enabledRoles);

        // Agent User IDP + AS User IDP: fully supported
        if (enabledRoles.contains(ROLE_AGENT_USER_IDP) && enabledRoles.contains(ROLE_AS_USER_IDP)) {
            logger.info("Detected co-existence: Agent User IDP + AS User IDP. "
                    + "Shared infrastructure beans (sessionMappingStore, sessionMappingBizService) "
                    + "will be provided by SharedCapabilityAutoConfiguration. "
                    + "Role-specific beans will use @ConditionalOnMissingBean to avoid conflicts.");
        }

        // Authorization Server + AS User IDP: fully supported
        if (enabledRoles.contains(ROLE_AUTHORIZATION_SERVER) && enabledRoles.contains(ROLE_AS_USER_IDP)) {
            logger.info("Detected co-existence: Authorization Server + AS User IDP. "
                    + "This is a common deployment pattern where the AS has embedded user authentication.");
        }

        // Agent + Agent IDP: supported
        if (enabledRoles.contains(ROLE_AGENT) && enabledRoles.contains(ROLE_AGENT_IDP)) {
            logger.info("Detected co-existence: Agent + Agent IDP. "
                    + "The Agent will act as its own Identity Provider.");
        }

        // Authorization Server + Resource Server: supported
        if (enabledRoles.contains(ROLE_AUTHORIZATION_SERVER) && enabledRoles.contains(ROLE_RESOURCE_SERVER)) {
            logger.info("Detected co-existence: Authorization Server + Resource Server. "
                    + "Combined deployment for small-scale scenarios.");
        }
    }
}
