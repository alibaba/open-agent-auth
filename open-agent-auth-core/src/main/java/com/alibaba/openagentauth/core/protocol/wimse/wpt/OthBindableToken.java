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
package com.alibaba.openagentauth.core.protocol.wimse.wpt;

import com.nimbusds.jose.JOSEException;

/**
 * Interface for tokens that can be bound to a Workload Proof Token (WPT)
 * via the oth (other tokens hashes) claim.
 * <p>
 * This interface abstracts the token binding mechanism, allowing WPT to be
 * cryptographically bound to various types of tokens without tight coupling
 * to specific token implementations. This follows the Dependency Inversion Principle
 * of SOLID design principles.
 * </p>
 * <p>
 * The oth claim in WPT is a JSON object containing hashes of other tokens
 * that this WPT is bound to. Each entry consists of a token type identifier
 * (the key) and a base64url-encoded SHA-256 hash of that token (the value).
 * </p>
 * <p>
 * Benefits of this abstraction:
 * <ul>
 *   <li><b>Flexibility:</b> Support for multiple token types (AOAT, Transaction Token, DPoP, etc.)</li>
 *   <li><b>Extensibility:</b> New token types can be added without modifying WptGenerator</li>
 *   <li><b>Testability:</b> Easy to create mock implementations for testing</li>
 *   <li><b>Protocol Compliance:</b> Fully aligned with WIMSE specification's flexible design</li>
 * </ul>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt-00.html">draft-ietf-wimse-wpt-00</a>
 * @since 1.0
 */
public interface OthBindableToken {

    /**
     * Returns the JWT string representation of this token.
     * <p>
     * The JWT string is used to compute the SHA-256 hash that will be included
     * in the WPT's oth claim. The hash is computed as:
     * {@code BASE64URL(SHA-256(ASCII(jwt_string)))}
     * </p>
     *
     * @return the complete JWT string (header.payload.signature)
     * @throws JOSEException if the JWT string is not available or cannot be retrieved
     */
    String getJwtString() throws JOSEException;

    /**
     * Returns the token type identifier used in the oth claim.
     * <p>
     * This identifier serves as the key in the oth claim's JSON object.
     * According to WIMSE specification, this should be a descriptive token type
     * identifier that uniquely identifies the token type.
     * </p>
     * <p>
     * Examples:
     * <ul>
     *   <li>{@code "aoat"} - Agent Operation Authorization Token</li>
     *   <li>{@code "tth"} - Transaction Token hash</li>
     *   <li>{@code "dpop"} - DPoP Token</li>
     * </ul>
     * </p>
     * <p>
     * The identifier should:
     * <ul>
     *   <li>Be lowercase and use hyphens or underscores for compound names</li>
     *   <li>Be descriptive and self-documenting</li>
     *   <li>Be consistent across the system</li>
     *   <li>Follow the naming conventions of the WIMSE specification</li>
     * </ul>
     * </p>
     *
     * @return the token type identifier (e.g., "aoat", "tth", "dpop")
     */
    String getTokenType();

}
