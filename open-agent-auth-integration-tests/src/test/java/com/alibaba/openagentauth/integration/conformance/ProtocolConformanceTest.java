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

import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marker annotation for protocol conformance tests.
 * <p>
 * This annotation marks a test class as a protocol conformance test that validates
 * the framework's adherence to external standard protocols (OAuth 2.0, OpenID Connect,
 * WIMSE, etc.). Conformance tests are only executed when explicitly enabled via
 * environment variable or Maven profile.
 * </p>
 * <p>
 * <b>Usage:</b>
 * <pre>
 * &#64;ProtocolConformanceTest(
 *     protocol = "OAuth 2.0 PAR",
 *     reference = "RFC 9126"
 * )
 * class ParConformanceTest {
 *     // test methods
 * }
 * </pre>
 * </p>
 * <p>
 * <b>Running Conformance Tests:</b>
 * </p>
 * <ul>
 *   <li>Maven profile: {@code mvn test -P protocol-conformance}</li>
 *   <li>Environment variable: {@code ENABLE_INTEGRATION_TESTS=true mvn test}</li>
 *   <li>Script: {@code ./scripts/run-conformance-tests.sh}</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0</a>
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
 * @since 1.0
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@ExtendWith(ProtocolConformanceTestCondition.class)
public @interface ProtocolConformanceTest {

    /**
     * Description of the protocol conformance test.
     *
     * @return the test description
     */
    String value() default "";

    /**
     * The protocol being tested (e.g., "OAuth 2.0 Token Endpoint", "OIDC Discovery").
     *
     * @return the protocol name
     */
    String protocol() default "";

    /**
     * The specification reference (e.g., "RFC 6749 §5", "OpenID Connect Discovery 1.0").
     *
     * @return the specification reference
     */
    String reference() default "";

    /**
     * Required services for this conformance test.
     * List of host:port combinations that must be reachable for this test to execute.
     *
     * @return array of required service addresses
     */
    String[] requiredServices() default {};
}
