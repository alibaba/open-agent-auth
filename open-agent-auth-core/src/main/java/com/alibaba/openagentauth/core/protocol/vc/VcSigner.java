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

import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.nimbusds.jose.JOSEException;

/**
 * Interface for signing Verifiable Credentials.
 * <p>
 * This interface defines the contract for signing Verifiable Credentials to create
 * JWT-based Verifiable Credentials (JWT-VC). The resulting JWT can be used as
 * the sourcePromptCredential in the evidence claim.
 * </p>
 * <p>
 * According to draft-liu-agent-operation-authorization-01, the agent client generates
 * the source prompt VC using its local private key and signs it using RS256.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public interface VcSigner {

    /**
     * Signs a Verifiable Credential and returns it as a JWT string.
     * <p>
     * This method takes a VerifiableCredential object, converts it to JWT format,
     * signs it using the configured signing key, and returns the serialized JWT.
     * </p>
     * <p>
     * The resulting JWT will have the structure:
     * <pre>
     * header: { "alg": "RS256", "typ": "JWT", "kid": "..." }
     * payload: { VC claims including type, credentialSubject, issuer, etc. }
     * signature: RS256 signature over the header and payload
     * </pre>
     * </p>
     *
     * @param credential the VerifiableCredential to sign
     * @return the signed JWT string
     * @throws JOSEException if signing fails
     * @throws IllegalArgumentException if the credential is invalid
     */
    String sign(VerifiableCredential credential) throws JOSEException;

    /**
     * Gets the key ID (kid) used for signing.
     * <p>
     * This method returns the key identifier that will be included in the JWT header.
     * The kid is used by verifiers to locate the corresponding public key in the JWKS.
     * </p>
     *
     * @return the key ID
     */
    String getKeyId();

    /**
     * Gets the issuer identifier used for signing.
     * <p>
     * This method returns the issuer that will be set in the JWT iss claim.
     * </p>
     *
     * @return the issuer identifier
     */
    String getIssuer();
}
