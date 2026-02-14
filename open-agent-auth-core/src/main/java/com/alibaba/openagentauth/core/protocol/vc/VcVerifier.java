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

import com.alibaba.openagentauth.core.exception.workload.VcVerificationException;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;

import java.text.ParseException;

/**
 * Interface for verifying Verifiable Credentials.
 * <p>
 * This interface defines the contract for verifying JWT-based Verifiable Credentials (JWT-VC).
 * Implementations should perform comprehensive validation including:
 * </p>
 * <ul>
 *   <li>JWT parsing and structure validation</li>
 *   <li>Algorithm validation</li>
 *   <li>Signature verification using JWKS</li>
 *   <li>Required claims validation</li>
 *   <li>Issuer validation</li>
 *   <li>Time-based validation (expiration, issue time)</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public interface VcVerifier {

    /**
     * Verifies a JWT-based Verifiable Credential and returns the parsed credential.
     * <p>
     * This method performs comprehensive validation of the JWT-VC including:
     * <ul>
     *   <li>JWT parsing and algorithm validation</li>
     *   <li>Signature verification using public keys from JWKS</li>
     *   <li>Required claims presence and validity checks</li>
     *   <li>Issuer validation (if configured)</li>
     *   <li>Time-based validation (expiration, not-before, max age)</li>
     * </ul>
     * </p>
     *
     * @param jwtVc the JWT string representing the Verifiable Credential
     * @return the parsed and verified VerifiableCredential
     * @throws ParseException if the JWT cannot be parsed
     * @throws VcVerificationException if any validation fails, including:
     *         <ul>
     *           <li>Unsupported algorithm (VC-INVALID-ALGORITHM)</li>
     *           <li>Signature verification failure (VC-INVALID-SIGNATURE)</li>
     *           <li>Missing or invalid claims (VC-MISSING-CLAIM, VC-INVALID-TYPE)</li>
     *           <li>Issuer mismatch (VC-INVALID-ISSUER)</li>
     *           <li>Expired credential (VC-EXPIRED)</li>
     *           <li>Credential not yet valid (VC-NOT-YET-VALID)</li>
     *           <li>Credential exceeds maximum age (VC-EXCEEDS-MAX-AGE)</li>
     *           <li>Public key not found (VC-KEY-NOT-FOUND)</li>
     *         </ul>
     */
    VerifiableCredential verify(String jwtVc) throws ParseException, VcVerificationException;

    /**
     * Sets the expected issuer for verification.
     * <p>
     * If set, the verifier will reject credentials with a different issuer.
     * This is used to ensure credentials are issued by a trusted source.
     * </p>
     *
     * @param issuer the expected issuer URI
     */
    void setExpectedIssuer(String issuer);

    /**
     * Gets the expected issuer for verification.
     *
     * @return the expected issuer, or null if not set
     */
    String getExpectedIssuer();
}