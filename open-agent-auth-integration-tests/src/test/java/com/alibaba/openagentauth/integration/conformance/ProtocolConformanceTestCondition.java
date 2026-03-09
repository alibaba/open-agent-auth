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
package com.alibaba.openagentauth.integration.conformance;

import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.Optional;

/**
 * JUnit 5 condition for enabling protocol conformance tests only in specified environments.
 * <p>
 * This condition checks if conformance tests should be enabled based on:
 * </p>
 * <ul>
 *   <li>The presence of the {@link ProtocolConformanceTest} annotation</li>
 *   <li>The {@code ENABLE_INTEGRATION_TESTS} environment variable</li>
 *   <li>The {@code protocol-conformance} Maven profile</li>
 *   <li>Availability of required services</li>
 * </ul>
 *
 * @since 1.0
 */
public class ProtocolConformanceTestCondition implements ExecutionCondition {

    private static final String ENABLE_INTEGRATION_TESTS = "ENABLE_INTEGRATION_TESTS";
    private static final String CONFORMANCE_PROFILE = "protocol-conformance";
    private static final int SERVICE_CHECK_TIMEOUT_MS = 1000;

    @Override
    public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
        Optional<ProtocolConformanceTest> annotation = context.getElement()
                .map(element -> element.getAnnotation(ProtocolConformanceTest.class));

        if (annotation.isEmpty()) {
            return ConditionEvaluationResult.enabled("Not a protocol conformance test");
        }

        if (!isConformanceTestsEnabled()) {
            return ConditionEvaluationResult.disabled(
                    "Protocol conformance tests are disabled. "
                    + "Enable them by setting " + ENABLE_INTEGRATION_TESTS + "=true "
                    + "or using Maven profile: mvn test -P " + CONFORMANCE_PROFILE
            );
        }

        String[] requiredServices = annotation.get().requiredServices();
        if (requiredServices.length > 0 && !checkRequiredServices(requiredServices)) {
            return ConditionEvaluationResult.disabled(
                    "Required services are not available: " + Arrays.toString(requiredServices)
            );
        }

        return ConditionEvaluationResult.enabled("Protocol conformance tests are enabled");
    }

    private boolean isConformanceTestsEnabled() {
        String envValue = System.getenv(ENABLE_INTEGRATION_TESTS);
        if ("true".equalsIgnoreCase(envValue)) {
            return true;
        }

        String sysPropValue = System.getProperty(ENABLE_INTEGRATION_TESTS);
        if ("true".equalsIgnoreCase(sysPropValue)) {
            return true;
        }

        String mavenProfile = System.getProperty("maven.profile");
        return CONFORMANCE_PROFILE.equals(mavenProfile);
    }

    private boolean checkRequiredServices(String[] requiredServices) {
        for (String service : requiredServices) {
            if (!isServiceAvailable(service)) {
                return false;
            }
        }
        return true;
    }

    private boolean isServiceAvailable(String service) {
        if (!service.contains(":")) {
            return true;
        }

        String[] parts = service.split(":");
        String host = parts[0];
        int port;
        try {
            port = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return false;
        }

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), SERVICE_CHECK_TIMEOUT_MS);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
