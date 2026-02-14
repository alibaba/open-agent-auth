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
package com.alibaba.openagentauth.framework.orchestration.test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * Test helper class for generating JWT tokens for testing purposes.
 * <p>
 * This class provides utility methods to generate valid WIT, WPT, and AOAT tokens
 * for unit testing without requiring complex setup.
 * </p>
 */
public class JwtTestHelper {

    private static RSAKey signingKey;

    static {
        try {
            signingKey = new RSAKeyGenerator(2048)
                    .keyID("test-key-id")
                    .generate();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to generate test signing key", e);
        }
    }

    /**
     * Generates a valid WIT JWT token string.
     *
     * @return a valid WIT JWT token string
     * @throws Exception if token generation fails
     */
    public static String generateValidWit() throws Exception {
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("wimse://example.com")
                .subject("agent-001")
                .expirationTime(Date.from(expiration))
                .issueTime(Date.from(now))
                .jwtID(UUID.randomUUID().toString())
                .claim("cnf", Map.of(
                        "jwk", Map.of(
                                "kty", "RSA",
                                "e", signingKey.getPublicExponent().toString(),
                                "n", signingKey.getModulus().toString()
                        )
                ))
                .claim("agent_identity", Map.of(
                        "version", "1.0",
                        "id", "agent-001",
                        "issuer", "wimse://example.com",
                        "issued_to", "user-12345"
                ))
                .build();

        return signJwt(claimsSet);
    }

    /**
     * Generates a valid WPT JWT token string.
     *
     * @return a valid WPT JWT token string
     * @throws Exception if token generation fails
     */
    public static String generateValidWpt() throws Exception {
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("wimse://example.com")
                .subject("workload-001")
                .expirationTime(Date.from(expiration))
                .issueTime(Date.from(now))
                .jwtID(UUID.randomUUID().toString())
                .claim("wth", "wit-hash")
                .build();

        return signJwt(claimsSet);
    }

    /**
     * Generates a valid AOAT JWT token string.
     *
     * @return a valid AOAT JWT token string
     * @throws Exception if token generation fails
     */
    public static String generateValidAoat() throws Exception {
        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(3600);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://as.example.com")
                .subject("user-12345")
                .audience("https://api.example.com")
                .expirationTime(Date.from(expiration))
                .issueTime(Date.from(now))
                .jwtID(UUID.randomUUID().toString())
                .claim("operation_proposal", "allow { true }")
                .claim("agent_identity", java.util.Map.of(
                        "version", "1.0",
                        "id", "agent-001",
                        "issuer", "wimse://example.com",
                        "issued_to", "user-12345"
                ))
                .claim("agent_operation_authorization", java.util.Map.of(
                        "policy_id", "op-001",
                        "operation_type", "query",
                        "allowed_resources", java.util.List.of("/api/resource")
                ))
                .build();

        return signJwt(claimsSet);
    }

    /**
     * Signs a JWT claims set with the test signing key.
     *
     * @param claimsSet the JWT claims set to sign
     * @return a signed JWT string
     * @throws Exception if signing fails
     */
    private static String signJwt(JWTClaimsSet claimsSet) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKey.getKeyID())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        JWSSigner signer = new RSASSASigner(signingKey);
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    /**
     * Gets the public key for token verification.
     *
     * @return the public JWK
     */
    public static JWK getPublicKey() {
        return signingKey.toPublicJWK();
    }
}
