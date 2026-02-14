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

/**
 * Interface for detecting the application role in the Open Agent Auth framework.
 * <p>
 * This interface allows the framework to automatically identify the role of the current
 * application and configure appropriate components based on that role. Role detection can
 * be performed through various mechanisms such as configuration files, environment variables,
 * or annotations.
 * </p>
 *
 * <h3>Implementation Guidelines:</h3>
 * <ul>
 *   <li>Implementations should be thread-safe and idempotent</li>
 *   <li>Role detection should be performed once and cached for performance</li>
 *   <li>Multiple detection mechanisms can be combined for flexibility</li>
 *   <li>Clear error messages should be provided when role cannot be determined</li>
 * </ul>
 *
 * <h3>Default Implementation:</h3>
 * <p>
 * The framework provides {@link PropertyBasedRoleDetector} which detects role based on
 * configuration properties. Custom implementations can be created for alternative
 * detection strategies.
 * </p>
 *
 * @see ApplicationRole
 * @see PropertyBasedRoleDetector
 * @since 1.0
 */
public interface RoleDetector {
    
    /**
     * Detects the role of the current application.
     * <p>
     * This method should determine the role through the configured detection mechanism
     * and return the corresponding {@link ApplicationRole}. The detection should be
     * deterministic and consistent across multiple calls.
     * </p>
     *
     * @return the detected application role
     * @throws IllegalStateException if the role cannot be determined
     */
    ApplicationRole detectRole();
    
    /**
     * Checks if the application is configured as a specific role.
     * <p>
     * This is a convenience method that combines {@link #detectRole()} with role comparison.
     * </p>
     *
     * @param role the role to check
     * @return true if the application is configured as the specified role
     */
    default boolean isRole(ApplicationRole role) {
        return detectRole() == role;
    }
    
    /**
     * Checks if the application is configured as an IDP (any IDP type).
     * <p>
     * This includes AGENT_USER_IDP, AGENT_IDP, and AS_USER_IDP.
     * </p>
     *
     * @return true if the application is an IDP
     */
    default boolean isIdp() {
        ApplicationRole role = detectRole();
        return role == ApplicationRole.AGENT_USER_IDP ||
               role == ApplicationRole.AGENT_IDP ||
               role == ApplicationRole.AS_USER_IDP;
    }
    
    /**
     * Checks if the application is configured as a server (Authorization Server or Resource Server).
     *
     * @return true if the application is a server
     */
    default boolean isServer() {
        ApplicationRole role = detectRole();
        return role == ApplicationRole.AUTHORIZATION_SERVER ||
               role == ApplicationRole.RESOURCE_SERVER;
    }
}
