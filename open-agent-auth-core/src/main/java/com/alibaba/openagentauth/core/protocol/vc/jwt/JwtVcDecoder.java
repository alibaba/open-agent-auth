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
package com.alibaba.openagentauth.core.protocol.vc.jwt;

import com.alibaba.openagentauth.core.model.evidence.Proof;
import com.alibaba.openagentauth.core.model.evidence.UserInputEvidence;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;

/**
 * Decoder for parsing JWT strings into VerifiableCredential objects.
 * <p>
 * This class handles the conversion of JWT-based Verifiable Credentials into
 * VerifiableCredential model objects. It extracts JWT claims and maps them to
 * VC fields according to the W3C VC Data Model and draft-liu-agent-operation-authorization-01.
 * </p>
 * <p>
 * <b>Claim Mapping:</b>
 * <ul>
 *   <li><b>Standard JWT Claims:</b>
 *     <ul>
 *       <li>jti (JWT ID) → credential identifier</li>
 *       <li>iss (issuer) → JWT issuer (different from VC issuer)</li>
 *       <li>sub (subject) → credential subject identifier</li>
 *       <li>iat (issued at) → Unix timestamp</li>
 *       <li>exp (expiration) → Unix timestamp</li>
 *     </ul>
 *   </li>
 *   <li><b>W3C VC Custom Claims:</b>
 *     <ul>
 *       <li>type → credential type (e.g., "VerifiableCredential")</li>
 *       <li>credentialSubject → the subject of the credential (e.g., UserInputEvidence)</li>
 *       <li>issuer → W3C VC issuer (URI string)</li>
 *       <li>issuanceDate → ISO 8601 timestamp</li>
 *       <li>expirationDate → ISO 8601 timestamp</li>
 *       <li>proof → cryptographic proof information</li>
 *     </ul>
 *   </li>
 * </ul>
 * </p>
 * <p>
 * <b>Usage Example:</b>
 * <pre>{@code
 * String jwtVc = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
 * VerifiableCredential credential = JwtVcDecoder.decode(jwtVc);
 * }</pre>
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @see <a href="https://www.w3.org/TR/vc-data-model/">W3C VC Data Model</a>
 * @since 1.0
 */
public class JwtVcDecoder {

    /**
     * ObjectMapper for JSON conversion operations.
     * <p>
     * Used to convert Map objects to strongly-typed model classes.
     * </p>
     */
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Decodes a JWT string to a VerifiableCredential object.
     * <p>
     * This method performs the following steps:
     * <ol>
     *   <li>Parses the JWT string into a SignedJWT object</li>
     *   <li>Extracts the JWT claims set</li>
     *   <li>Converts claims to VerifiableCredential using {@link #convertFromClaims(JWTClaimsSet)}</li>
     * </ol>
     * </p>
     * <p>
     * The method handles both standard JWT claims and W3C VC-specific custom claims.
     * </p>
     *
     * @param jwtVc the JWT string to decode
     * @return the decoded VerifiableCredential object
     * @throws ParseException if the JWT cannot be parsed or is malformed
     * @throws NullPointerException if jwtVc is null
     */
    public static VerifiableCredential decode(String jwtVc) throws ParseException {
        SignedJWT signedJwt = SignedJWT.parse(jwtVc);
        JWTClaimsSet claimsSet = signedJwt.getJWTClaimsSet();
        
        return convertFromClaims(claimsSet);
    }

    /**
     * Converts JWT claims to a VerifiableCredential.
     * <p>
     * This method maps JWT claims to VC fields according to the specification.
     * It first initializes the builder with standard JWT claims using {@link #getBuilder(JWTClaimsSet)},
     * then processes W3C VC-specific custom claims.
     * </p>
     * <p>
     * <b>Custom Claims Processing:</b>
     * <ul>
     *   <li><b>credentialSubject:</b> Converts from Map or UserInputEvidence object</li>
     *   <li><b>issuer:</b> Extracts as string (W3C VC issuer)</li>
     *   <li><b>issuanceDate:</b> Extracts as string (ISO 8601)</li>
     *   <li><b>expirationDate:</b> Extracts as string (ISO 8601)</li>
     *   <li><b>proof:</b> Converts from Map or Proof object</li>
     * </ul>
     * </p>
     * <p>
     * Note: Conversion failures for custom claims are logged for debugging purposes but are silently ignored to allow
     * partial decoding. This is intentional to support different VC profiles.
     * </p>
     *
     * @param claimsSet the JWT claims set
     * @return the VerifiableCredential
     */
    private static VerifiableCredential convertFromClaims(JWTClaimsSet claimsSet) {

        // Standard JWT claims
        VerifiableCredential.Builder builder = getBuilder(claimsSet);

        // Process credentialSubject
        Object credentialSubjectObj = claimsSet.getClaim("credentialSubject");
        if (credentialSubjectObj instanceof UserInputEvidence) {
            builder.credentialSubject((UserInputEvidence) credentialSubjectObj);
        } else if (credentialSubjectObj instanceof java.util.Map) {
            try {
                UserInputEvidence subject = OBJECT_MAPPER.convertValue(
                        credentialSubjectObj, UserInputEvidence.class);
                builder.credentialSubject(subject);
            } catch (Exception e) {
                // Log the error for debugging
                System.err.println("Failed to convert credentialSubject: " + e.getMessage());
                e.printStackTrace();
            }
        }

        // Process W3C VC issuer (different from JWT iss claim)
        Object issuerObj = claimsSet.getClaim("issuer");
        if (issuerObj != null) {
            builder.issuer(issuerObj.toString());
        }

        // Process issuanceDate
        Object issuanceDateObj = claimsSet.getClaim("issuanceDate");
        if (issuanceDateObj != null) {
            builder.issuanceDate(issuanceDateObj.toString());
        }

        // Process expirationDate
        Object expirationDateObj = claimsSet.getClaim("expirationDate");
        if (expirationDateObj != null) {
            builder.expirationDate(expirationDateObj.toString());
        }

        // Process proof
        Object proofObj = claimsSet.getClaim("proof");
        if (proofObj instanceof Proof) {
            builder.proof((Proof) proofObj);
        } else if (proofObj instanceof java.util.Map) {
            try {
                Proof proof = OBJECT_MAPPER.convertValue(proofObj, Proof.class);
                builder.proof(proof);
            } catch (Exception e) {
                // Log the error for debugging
                System.err.println("Failed to convert proof: " + e.getMessage());
                e.printStackTrace();
            }
        }

        return builder.build();
    }

    /**
     * Gets a builder for the VerifiableCredential initialized with standard JWT claims.
     * <p>
     * This method extracts standard JWT claims and initializes the builder:
     * <ul>
     *   <li>jti (JWT ID) → credential unique identifier</li>
     *   <li>iss (issuer) → JWT issuer</li>
     *   <li>sub (subject) → credential subject identifier</li>
     *   <li>iat (issued at) → Unix timestamp (seconds since epoch)</li>
     *   <li>exp (expiration) → Unix timestamp (seconds since epoch)</li>
     *   <li>type → credential type (e.g., "VerifiableCredential")</li>
     * </ul>
     * </p>
     * <p>
     * Time-based claims are converted from Date to Unix timestamp (seconds).
     * </p>
     *
     * @param claimsSet the JWT claims set
     * @return the builder initialized with standard claims
     */
    private static VerifiableCredential.Builder getBuilder(JWTClaimsSet claimsSet) {

        // Initialize builder
        VerifiableCredential.Builder builder = VerifiableCredential.builder();

        // Standard JWT claims
        builder.jti(claimsSet.getJWTID());
        builder.iss(claimsSet.getIssuer());
        builder.sub(claimsSet.getSubject());

        // Convert Date to Unix timestamp (seconds)
        if (claimsSet.getIssueTime() != null) {
            builder.iat(claimsSet.getIssueTime().getTime() / 1000);
        }
        if (claimsSet.getExpirationTime() != null) {
            builder.exp(claimsSet.getExpirationTime().getTime() / 1000);
        }

        // W3C VC type claim
        Object typeObj = claimsSet.getClaim("type");
        if (typeObj != null) {
            builder.type(typeObj.toString());
        }
        return builder;
    }
}