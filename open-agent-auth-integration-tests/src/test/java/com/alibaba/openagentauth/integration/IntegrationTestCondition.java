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
package com.alibaba.openagentauth.integration;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Arrays;
import java.util.Optional;

/**
 * JUnit 5 condition for enabling integration tests only in specified environments.
 * <p>
 * This condition checks if integration tests should be enabled based on:
 * </p>
 * <ul>
 *   <li>The presence of the {@link IntegrationTest} annotation</li>
 *   <li>The {@code ENABLE_INTEGRATION_TESTS} environment variable</li>
 *   <li>The {@code integration-test} Maven profile</li>
 * </ul>
 * <p>
 * <b>Configuration:</b>
 * </p>
 * <ul>
 *   <li>Environment Variable: {@code ENABLE_INTEGRATION_TESTS=true}</li>
 *   <li>Maven Profile: {@code mvn test -P integration-test}</li>
 * </ul>
 *
 * @since 1.0
 */
public class IntegrationTestCondition implements ExecutionCondition {

    private static final String ENABLE_INTEGRATION_TESTS = "ENABLE_INTEGRATION_TESTS";
    private static final String INTEGRATION_TEST_PROFILE = "integration-test";

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
        // Check if the test class is annotated with @IntegrationTest
        Optional<IntegrationTest> annotation = context.getElement()
                .map(element -> element.getAnnotation(IntegrationTest.class));

        if (annotation.isEmpty()) {
            // Not an integration test, enable it
            return ConditionEvaluationResult.enabled("Not an integration test");
        }

        // Check if integration tests are enabled
        boolean isEnabled = isIntegrationTestsEnabled();

        if (!isEnabled) {
            // Integration tests are disabled
            return ConditionEvaluationResult.disabled(
                    "Integration tests are disabled. " +
                    "Enable them by setting " + ENABLE_INTEGRATION_TESTS + "=true " +
                    "or using Maven profile: mvn test -P " + INTEGRATION_TEST_PROFILE
            );
        }

        // Check required services
        IntegrationTest integrationTestAnnotation = annotation.get();
        String[] requiredServices = integrationTestAnnotation.requiredServices();

        if (requiredServices.length > 0) {
            boolean allServicesAvailable = checkRequiredServices(requiredServices);
            
            if (!allServicesAvailable) {
                return ConditionEvaluationResult.disabled(
                        "Required services are not available: " + Arrays.toString(requiredServices)
                );
            }
        }

        return ConditionEvaluationResult.enabled("Integration tests are enabled");
    }

    /**
     * Check if integration tests are enabled.
     * 
     * @return true if integration tests are enabled, false otherwise
     */
    private boolean isIntegrationTestsEnabled() {
        // Check environment variable
        String envValue = System.getenv(ENABLE_INTEGRATION_TESTS);
        if ("true".equalsIgnoreCase(envValue)) {
            return true;
        }

        // Check system property (set by Maven profile)
        String sysPropValue = System.getProperty(ENABLE_INTEGRATION_TESTS);
        if ("true".equalsIgnoreCase(sysPropValue)) {
            return true;
        }

        // Check Maven profile
        String mavenProfile = System.getProperty("maven.profile");
        if (INTEGRATION_TEST_PROFILE.equals(mavenProfile)) {
            return true;
        }

        return false;
    }

    /**
     * Check if required services are available.
     * This is a simple implementation that checks if services are reachable.
     * 
     * @param requiredServices array of service names or host:port combinations
     * @return true if all required services are available, false otherwise
     */
    private boolean checkRequiredServices(String[] requiredServices) {
        for (String service : requiredServices) {
            if (!isServiceAvailable(service)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check if a single service is available.
     * 
     * @param service service name or host:port combination
     * @return true if the service is available, false otherwise
     */
    private boolean isServiceAvailable(String service) {
        // Simple implementation: try to connect to the service
        if (service.contains(":")) {
            String[] parts = service.split(":");
            String host = parts[0];
            int port;
            try {
                port = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                // Invalid port format, assume service is not available
                return false;
            }

            try (java.net.Socket socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress(host, port), 1000);
                return true;
            } catch (Exception e) {
                // Service is not available
                return false;
            }
        }

        // For service names, we could implement more sophisticated checks
        // For now, return true if the environment variable is set
        return true;
    }
}
