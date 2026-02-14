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
package com.alibaba.openagentauth.core.protocol.vc;

import java.time.Clock;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

/**
 * Simplified verification policy for Verifiable Credentials.
 * <p>
 * This class defines basic verification rules for validating Verifiable Credentials.
 * It allows customization of acceptable algorithms, expected issuer, clock settings,
 * and time-based validation parameters.
 * </p>
 * <p>
 * According to draft-liu-agent-operation-authorization-01, the evidence VC should be
 * verified using RS256 algorithm with proper time-based validation.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public class VcVerificationPolicy {

    /**
     * Default clock skew tolerance for timestamp validation.
     * <p>
     * This allows for minor time differences between systems (5 minutes).
     * </p>
     */
    private static final Duration DEFAULT_CLOCK_SKEW_TOLERANCE = Duration.ofMinutes(5);

    /**
     * Default maximum age for a Verifiable Credential.
     * <p>
     * Credentials older than 24 hours will be rejected.
     * </p>
     */
    private static final Duration DEFAULT_MAX_AGE = Duration.ofHours(24);

    /**
     * Set of allowed JWS algorithms for signature verification.
     * <p>
     * By default, supports RSA (RS256, RS384, RS512) and ECDSA (ES256, ES384, ES512) algorithms.
     * </p>
     */
    private final Set<String> allowedAlgorithms;

    /**
     * Expected issuer for the Verifiable Credential.
     * <p>
     * If set, the VC's issuer claim must match this value exactly.
     * This is used to ensure the credential is issued by a trusted source.
     * </p>
     */
    private String expectedIssuer;

    /**
     * Clock instance for time-based validation.
     * <p>
     * This allows for testing with fixed time and custom time zones.
     * Defaults to system UTC clock.
     * </p>
     */
    private Clock clock;

    /**
     * Clock skew tolerance for timestamp validation.
     * <p>
     * This accounts for minor time differences between systems issuing
     * and verifying credentials. The expiration time is extended by this
     * tolerance, and the issue time is reduced by this tolerance.
     * </p>
     */
    private Duration clockSkewTolerance;

    /**
     * Maximum allowed age for a Verifiable Credential.
     * <p>
     * Credentials issued before (current time - maxAge) will be rejected.
     * This prevents the use of stale credentials.
     * </p>
     */
    private Duration maxAge;

    /**
     * Creates a new VcVerificationPolicy with default settings.
     * <p>
     * Default settings:
     * <ul>
     *   <li>Allowed algorithms: RS256, RS384, RS512, ES256, ES384, ES512</li>
     *   <li>Clock: system UTC</li>
     *   <li>Clock skew tolerance: 5 minutes</li>
     *   <li>Maximum age: 24 hours</li>
     * </ul>
     * </p>
     */
    public VcVerificationPolicy() {
        this.allowedAlgorithms = new HashSet<>();
        this.allowedAlgorithms.add("RS256");
        this.allowedAlgorithms.add("RS384");
        this.allowedAlgorithms.add("RS512");
        this.allowedAlgorithms.add("ES256");
        this.allowedAlgorithms.add("ES384");
        this.allowedAlgorithms.add("ES512");
        this.clock = Clock.systemUTC();
        this.clockSkewTolerance = DEFAULT_CLOCK_SKEW_TOLERANCE;
        this.maxAge = DEFAULT_MAX_AGE;
    }

    /**
     * Checks if a JWS algorithm is allowed for signature verification.
     *
     * @param algorithm the JWS algorithm name (e.g., "RS256", "ES256")
     * @return true if the algorithm is allowed, false otherwise
     */
    public boolean isAlgorithmAllowed(String algorithm) {
        return allowedAlgorithms.contains(algorithm);
    }

    /**
     * Gets the expected issuer for verification.
     *
     * @return the expected issuer, or null if not set
     */
    public String getExpectedIssuer() {
        return expectedIssuer;
    }

    /**
     * Sets the expected issuer for verification.
     * <p>
     * If set, the VC's issuer claim must match this value exactly.
     * </p>
     *
     * @param expectedIssuer the expected issuer
     */
    public void setExpectedIssuer(String expectedIssuer) {
        this.expectedIssuer = expectedIssuer;
    }

    /**
     * Gets the clock instance used for time-based validation.
     *
     * @return the clock
     */
    public Clock getClock() {
        return clock;
    }

    /**
     * Gets the clock skew tolerance.
     *
     * @return the clock skew tolerance
     */
    public Duration getClockSkewTolerance() {
        return clockSkewTolerance;
    }

    /**
     * Gets the maximum allowed age for a Verifiable Credential.
     *
     * @return the maximum age
     */
    public Duration getMaxAge() {
        return maxAge;
    }
}