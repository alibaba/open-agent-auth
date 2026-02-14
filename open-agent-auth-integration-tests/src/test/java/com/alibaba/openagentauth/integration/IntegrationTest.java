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

import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marker annotation for integration tests.
 * <p>
 * This annotation marks a test class as an integration test that requires
 * external services or infrastructure to be running. Integration tests are
 * only executed when the integration-test profile is active or when the
 * ENABLE_INTEGRATION_TESTS environment variable is set to "true".
 * </p>
 * <p>
 * <b>Usage:</b>
 * <pre>
 * &#64;IntegrationTest
 * class MyIntegrationTest {
 *     // test methods
 * }
 * </pre>
 * </p>
 * <p>
 * <b>Running Integration Tests:</b>
 * </p>
 * <ul>
 *   <li>Using Maven profile: <code>mvn test -P integration-test</code></li>
 *   <li>Using environment variable: <code>ENABLE_INTEGRATION_TESTS=true mvn test</code></li>
 *   <li>From IDE: Set environment variable <code>ENABLE_INTEGRATION_TESTS=true</code></li>
 * </ul>
 *
 * @since 1.0
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(IntegrationTestCondition.class)
public @interface IntegrationTest {
    /**
     * Description of the integration test.
     * 
     * @return the test description
     */
    String value() default "";
    
    /**
     * Required services for this integration test.
     * List of service names that must be running for this test to execute.
     * 
     * @return array of required service names
     */
    String[] requiredServices() default {};
}
