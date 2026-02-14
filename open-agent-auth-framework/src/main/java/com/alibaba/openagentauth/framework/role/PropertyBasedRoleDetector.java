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
package com.alibaba.openagentauth.framework.role;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default implementation of {@link RoleDetector} that detects role based on configuration properties.
 * <p>
 * This detector reads role configuration from a properties map, typically loaded from
 * application.properties, application.yml, or environment variables. It supports multiple
 * configuration keys with a priority order:
 * </p>
 *
 * <ol>
 *   <li>{@code open-agent-auth.role} - Primary configuration key</li>
 *   <li>{@code open-agent-auth.agent-auth.role} - Alternative configuration key (legacy support)</li>
 *   <li>Environment variables with {@code OPEN_AGENT_AUTH_ROLE_} prefix</li>
 * </ol>
 *
 * <h3>Configuration Examples:</h3>
 * <pre>
 * # application.properties
 * open-agent-auth.role=authorization-server
 *
 * # application.yml
 * open-agent-auth:
 *   role: resource-server
 *
 * # Environment variable
 * export OPEN_AGENT_AUTH_ROLE=agent-user-idp
 * </pre>
 *
 * <h3>Thread Safety:</h3>
 * <p>
 * This implementation is thread-safe and caches the detected role for performance.
 * The role is detected on first call and reused for subsequent calls.
 * </p>
 *
 * @see RoleDetector
 * @see ApplicationRole
 * @since 1.0
 */
public class PropertyBasedRoleDetector implements RoleDetector {
    
    private static final Logger logger = LoggerFactory.getLogger(PropertyBasedRoleDetector.class);
    
    private static final String PRIMARY_CONFIG_KEY = "open-agent-auth.role";
    private static final String ALTERNATIVE_CONFIG_KEY = "open-agent-auth.agent-auth.role";
    private static final String ROLE_NOT_CONFIGURED_MESSAGE = 
        "Application role is not configured. Please set 'open-agent-auth.role' property. " +
        "Valid values: agent-user-idp, agent-idp, as-user-idp, authorization-server, resource-server, agent";
    
    private final Map<String, String> properties;
    private volatile ApplicationRole cachedRole;
    
    /**
     * Creates a new property-based role detector.
     *
     * @param properties the configuration properties
     * @throws IllegalArgumentException if properties is null
     */
    public PropertyBasedRoleDetector(Map<String, String> properties) {
        this.properties = ValidationUtils.validateNotNull(properties, "Properties");
        logger.info("PropertyBasedRoleDetector initialized with {} properties", properties.size());
    }
    
    /**
     * Creates a new property-based role detector with system properties and environment variables.
     * <p>
     * This constructor automatically loads properties from:
     * </p>
     * <ul>
     *   <li>System properties ({@link System#getProperties()})</li>
     *   <li>Environment variables ({@link System#getenv()})</li>
     * </ul>
     */
    public PropertyBasedRoleDetector() {
        this(createDefaultProperties());
    }
    
    @Override
    public ApplicationRole detectRole() {
        if (cachedRole != null) {
            return cachedRole;
        }
        
        synchronized (this) {
            if (cachedRole != null) {
                return cachedRole;
            }
            
            ApplicationRole detectedRole = detectRoleInternal();
            cachedRole = detectedRole;
            
            logger.info("Detected application role: {} ({})", 
                detectedRole, detectedRole.getDescription());
            
            return detectedRole;
        }
    }
    
    /**
     * Internal method to detect role from properties.
     *
     * @return the detected role
     * @throws IllegalStateException if role cannot be determined
     */
    private ApplicationRole detectRoleInternal() {
        String roleCode = findRoleCode();
        
        if (ValidationUtils.isNullOrEmpty(roleCode)) {
            throw new IllegalStateException(ROLE_NOT_CONFIGURED_MESSAGE);
        }
        
        ApplicationRole role = ApplicationRole.fromCode(roleCode.trim().toLowerCase());
        
        if (role == null) {
            throw new IllegalStateException(
                String.format("Invalid application role: '%s'. Valid values are: %s",
                    roleCode,
                    String.join(", ", getAllRoleCodes()))
            );
        }
        
        return role;
    }
    
    /**
     * Finds the role code from properties using priority order.
     *
     * @return the role code, or null if not found
     */
    private String findRoleCode() {

        // Check primary configuration key
        String roleCode = properties.get(PRIMARY_CONFIG_KEY);
        if (!ValidationUtils.isNullOrEmpty(roleCode)) {
            logger.debug("Role found from primary config key: {}", PRIMARY_CONFIG_KEY);
            return roleCode;
        }
        
        // Check alternative configuration key (legacy support)
        roleCode = properties.get(ALTERNATIVE_CONFIG_KEY);
        if (!ValidationUtils.isNullOrEmpty(roleCode)) {
            logger.debug("Role found from alternative config key: {}", ALTERNATIVE_CONFIG_KEY);
            return roleCode;
        }
        
        // Check environment variables
        for (Map.Entry<String, String> entry : properties.entrySet()) {
            String key = entry.getKey();
            if (key != null && key.toUpperCase().startsWith("OPEN_AGENT_AUTH_ROLE_")) {
                logger.debug("Role found from environment variable: {}", key);
                return entry.getValue();
            }
        }
        
        logger.warn("No role configuration found in properties");
        return null;
    }
    
    /**
     * Gets all valid role codes for error messages.
     *
     * @return array of role codes
     */
    private String[] getAllRoleCodes() {
        ApplicationRole[] roles = ApplicationRole.values();
        String[] codes = new String[roles.length];
        for (int i = 0; i < roles.length; i++) {
            codes[i] = roles[i].getCode();
        }
        return codes;
    }
    
    /**
     * Creates default properties from system properties and environment variables.
     *
     * @return map containing system properties and environment variables
     */
    private static Map<String, String> createDefaultProperties() {
        Map<String, String> props = new ConcurrentHashMap<>();
        
        // Add system properties
        System.getProperties().forEach((key, value) -> {
            if (key instanceof String && value instanceof String) {
                props.put((String) key, (String) value);
            }
        });
        
        // Add environment variables
        props.putAll(System.getenv());
        
        return props;
    }
}