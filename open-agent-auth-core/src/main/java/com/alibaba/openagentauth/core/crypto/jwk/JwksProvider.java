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
package com.alibaba.openagentauth.core.crypto.jwk;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.io.IOException;

/**
 * Interface for providing JSON Web Key Set (JWKS) for verifying VC signatures.
 * <p>
 * This interface abstracts the mechanism for retrieving public keys used to verify
 * Verifiable Credential signatures. Implementations can fetch keys from various
 * sources such as remote JWKS endpoints, local files, or in-memory storage.
 * </p>
 * <p>
 * According to draft-liu-agent-operation-authorization-01, the agent client publishes
 * its public keys in JWKS format at the well-known endpoint /.well-known/jwks.json.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517 - JSON Web Key (JWK)</a>
 * @since 1.0
 */
public interface JwksProvider {

    /**
     * Gets the JWK source for verifying signatures.
     * <p>
     * This method returns a JWKSource that can be used by JWT verifiers to obtain
     * the public keys needed to verify Verifiable Credential signatures.
     * </p>
     *
     * @return the JWK source
     * @throws IOException if an error occurs while retrieving keys
     */
    JWKSource<SecurityContext> getJwkSource() throws IOException;

    /**
     * Gets the complete JWK set.
     * <p>
     * This method returns all available public keys in the JWKS format.
     * </p>
     *
     * @return the JWK set
     * @throws IOException if an error occurs while retrieving keys
     */
    JWKSet getJwkSet() throws IOException;

    /**
     * Refreshes the cached keys.
     * <p>
     * This method forces a refresh of the cached public keys. Implementations
     * should clear any cached values and fetch fresh keys from the source.
     * </p>
     *
     * @throws IOException if an error occurs while refreshing keys
     */
    void refresh() throws IOException;

}
