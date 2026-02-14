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
package com.alibaba.openagentauth.spring.autoconfigure.util;

import com.alibaba.openagentauth.core.protocol.oidc.registry.InMemoryUserRegistry;
import com.alibaba.openagentauth.core.protocol.oidc.registry.UserRegistry;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.UserAuthenticationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for creating user registries from configuration.
 * <p>
 * This class provides static methods to create and populate user registries
 * from configuration properties, avoiding code duplication across different
 * auto-configuration classes.
 * </p>
 *
 * @since 1.0
 */
public class UserRegistryUtils {

    private static final Logger logger = LoggerFactory.getLogger(UserRegistryUtils.class);

    /**
     * Creates a user registry from capabilities user registry properties.
     * <p>
     * This method creates an in-memory user registry and populates it with
     * preset users from the capabilities configuration if enabled.
     * </p>
     *
     * @param userRegistryProps the user registry configuration properties from capabilities
     * @param roleName the name of the role (for logging purposes)
     * @return the configured user registry
     */
    public static UserRegistry createUserRegistryFromCapabilities(
            UserAuthenticationProperties.UserRegistryProperties userRegistryProps,
            String roleName) {
        logger.info("Creating UserRegistry bean for {} from capabilities", roleName);
        
        InMemoryUserRegistry registry = new InMemoryUserRegistry();
        
        // Load preset users from configuration
        if (userRegistryProps.isEnabled() && !userRegistryProps.getPresetUsers().isEmpty()) {
            var presetUsers = userRegistryProps.getPresetUsers();
            int loadedCount = 0;
            
            for (var userConfig : presetUsers) {
                registry.addUser(
                    userConfig.getUsername(),
                    userConfig.getPassword(),
                    userConfig.getSubject(),
                    userConfig.getEmail(),
                    userConfig.getName()
                );
                loadedCount++;
            }
            
            logger.info("Loaded {} preset users from capabilities configuration for {}", loadedCount, roleName);
        } else {
            logger.info("No preset users configured, user registry created empty for {}", roleName);
        }
        
        return registry;
    }

    private UserRegistryUtils() {
        // Utility class - prevent instantiation
    }
}