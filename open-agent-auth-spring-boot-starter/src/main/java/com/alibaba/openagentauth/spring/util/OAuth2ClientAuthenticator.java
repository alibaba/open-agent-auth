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
package com.alibaba.openagentauth.spring.util;

import com.alibaba.openagentauth.core.crypto.jwk.JwkUtils;
import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.verify.SignatureVerificationUtils;
import com.alibaba.openagentauth.core.protocol.oauth2.client.store.OAuth2ClientStore;
import com.alibaba.openagentauth.core.protocol.oauth2.client.model.OAuth2RegisteredClient;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

/**
 * Utility class for OAuth 2.0 server-side client authentication.
 * <p>
 * This class provides static methods for authenticating OAuth 2.0 clients
 * on the server side, supporting multiple authentication mechanisms as specified
 * in RFC 6749 Section 2.3 and RFC 7523.
 * </p>
 * <p>
 * <b>Supported Authentication Methods:</b></p>
 * <ul>
 *   <li><b>client_secret_basic (RFC 6749 Section 2.3.1)</b>: HTTP Basic authentication
 *       with client_id and client_secret</li>
 *   <li><b>private_key_jwt (RFC 7523 Section 2.2)</b>: JWT assertion signed with
 *       client's private key, verified using the client's published JWKS</li>
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-2.3">RFC 6749 - Client Authentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
 * @since 1.0
 */
public class OAuth2ClientAuthenticator {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2ClientAuthenticator.class);

    private static final String BASIC_AUTH_SCHEME = "Basic ";
    private static final String CLIENT_SECRET_BASIC = "client_secret_basic";
    private static final String PRIVATE_KEY_JWT = "private_key_jwt";
    private static final String JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /**
     * The key manager for resolving verification keys from the JWKS infrastructure.
     * <p>
     * This delegates key resolution to the standard {@link KeyManager} infrastructure,
     * which uses the {@code JwksConsumerKeyResolver} to fetch public keys from configured
     * JWKS consumers (e.g., Agent IDP's JWKS endpoint). This ensures consistent key management
     * with WIT verification and other signature validation flows.
     * </p>
     */
    private final KeyManager keyManager;

    /**
     * The key definition name used to resolve the verification key from the {@link KeyManager}.
     * <p>
     * This corresponds to a key definition in the infrastructure configuration
     * (e.g., {@code wit-verification}), which maps to a JWKS consumer for the Agent IDP.
     * The same key definition is used by {@code WitValidator} for WIT signature verification,
     * ensuring consistent key resolution across all Agent IDP signature verification flows.
     * </p>
     */
    private final String verificationKeyId;

    /**
     * Creates a new OAuth2ClientAuthenticator with the specified key manager and verification key ID.
     *
     * @param keyManager the key manager for resolving verification keys
     * @param verificationKeyId the key definition name for resolving the Agent IDP verification key
     * @throws IllegalArgumentException if any parameter is null
     */
    public OAuth2ClientAuthenticator(KeyManager keyManager, String verificationKeyId) {
        this.keyManager = ValidationUtils.validateNotNull(keyManager, "Key manager");
        this.verificationKeyId = ValidationUtils.validateNotNull(verificationKeyId, "Verification key ID");
        logger.info("OAuth2ClientAuthenticator initialized with KeyManager and verificationKeyId: {}", verificationKeyId);
    }

    /**
     * Authenticates the client using the appropriate method based on the request parameters.
     * <p>
     * This method automatically detects the authentication method:
     * </p>
     * <ul>
     *   <li>If {@code client_assertion} and {@code client_assertion_type} are present in the
     *       request body, uses {@code private_key_jwt} authentication (RFC 7523)</li>
     *   <li>If an {@code Authorization} header with Basic scheme is present, uses
     *       {@code client_secret_basic} authentication (RFC 6749 Section 2.3.1)</li>
     * </ul>
     *
     * @param authorizationHeader the Authorization header value (may be null)
     * @param requestBody the request body parameters (may be null)
     * @param clientStore the client store for retrieving client information
     * @return the authenticated client ID
     * @throws FrameworkOAuth2TokenException if authentication fails
     */
    public String authenticateClient(
            String authorizationHeader,
            Map<String, String> requestBody,
            OAuth2ClientStore clientStore) {

        // Check for client_assertion in request body (private_key_jwt takes precedence)
        if (requestBody != null) {
            String clientAssertion = requestBody.get("client_assertion");
            String clientAssertionType = requestBody.get("client_assertion_type");

            if (!ValidationUtils.isNullOrEmpty(clientAssertion) && !ValidationUtils.isNullOrEmpty(clientAssertionType)) {
                logger.debug("Client assertion detected, using private_key_jwt authentication (assertion_type: {})",
                        clientAssertionType);
                return authenticateWithClientAssertion(clientAssertion, clientAssertionType, requestBody, clientStore);
            }
        }

        // Fall back to Basic Auth
        logger.debug("No client assertion found, falling back to client_secret_basic authentication");
        return authenticateWithBasicAuth(authorizationHeader, clientStore);
    }

    /**
     * Authenticates the client using HTTP Basic authentication (RFC 6749 Section 2.3.1).
     *
     * @param authorizationHeader the Authorization header value
     * @param clientStore the client store for retrieving client information
     * @return the authenticated client ID
     * @throws FrameworkOAuth2TokenException if authentication fails
     */
    public static String authenticateWithBasicAuth(String authorizationHeader, OAuth2ClientStore clientStore) {

        // Validate Authorization header is present
        if (ValidationUtils.isNullOrEmpty(authorizationHeader)) {
            logger.error("Authorization header is missing");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Authorization header is missing");
        }

        // Validate Basic Auth scheme
        if (!authorizationHeader.startsWith(BASIC_AUTH_SCHEME)) {
            logger.error("Invalid authentication scheme, expected 'Basic'");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Only Basic authentication is supported");
        }

        // Extract and decode credentials
        String base64Credentials = authorizationHeader.substring(BASIC_AUTH_SCHEME.length()).trim();
        String credentials;
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(base64Credentials);
            credentials = new String(decodedBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            logger.error("Failed to decode Base64 credentials", e);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid Base64 encoding");
        }

        // Parse client_id:client_secret
        String[] parts = credentials.split(":", 2);
        if (parts.length != 2) {
            logger.error("Invalid credentials format, expected 'client_id:client_secret'");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid credentials format");
        }

        String clientId = parts[0];
        String clientSecret = parts[1];

        // Validate client ID is not empty
        if (ValidationUtils.isNullOrEmpty(clientId)) {
            logger.error("Client ID is empty");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client ID is required");
        }

        // Retrieve client from client store
        OAuth2RegisteredClient client = clientStore.retrieve(clientId);
        if (client == null) {
            logger.error("Client not found: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client not registered");
        }

        // Validate client secret
        String storedSecret = client.getClientSecret();
        if (ValidationUtils.isNullOrEmpty(storedSecret)) {
            logger.error("Client {} has no secret configured (public client)", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client is not configured for Basic authentication");
        }

        if (!storedSecret.equals(clientSecret)) {
            logger.error("Invalid client secret for client: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid client secret");
        }

        String authMethod = client.getTokenEndpointAuthMethod();
        if (authMethod != null && !CLIENT_SECRET_BASIC.equals(authMethod)) {
            logger.error("Client {} is not configured for client_secret_basic, configured method: {}", clientId, authMethod);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client is not configured for Basic authentication");
        }

        logger.debug("Client authenticated via client_secret_basic: {}", clientId);
        return clientId;
    }

    /**
     * Authenticates the client using JWT-based client assertion (RFC 7523).
     * <p>
     * This method supports two modes of client identification:
     * </p>
     * <ol>
     *   <li><b>WIMSE mode</b>: When the request body contains a {@code client_id} parameter,
     *       it is used as the client identifier. The JWT's {@code sub} claim is validated
     *       against this {@code client_id}. This supports WIMSE workload identity tokens
     *       where {@code iss} (trust domain) differs from {@code sub} (workload ID).</li>
     *   <li><b>Standard RFC 7523 mode</b>: When no {@code client_id} is in the request body,
     *       the JWT's {@code iss} claim is used as the client identifier, and {@code sub}
     *       must match {@code iss} per RFC 7523 Section 3.</li>
     * </ol>
     * <p>
     * The following claims are validated:
     * </p>
     * <ul>
     *   <li><b>sub</b>: Must match the resolved client_id</li>
     *   <li><b>exp</b>: Must not be expired</li>
     * </ul>
     *
     * @param clientAssertion the JWT assertion
     * @param clientAssertionType the assertion type (must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer)
     * @param requestBody the request body parameters containing optional client_id
     * @param clientStore the client store for retrieving client information
     * @return the authenticated client ID
     * @throws FrameworkOAuth2TokenException if authentication fails
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc7523">RFC 7523 - JWT Profile for OAuth 2.0 Client Authentication</a>
     * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/">draft-ietf-wimse-workload-creds</a>
     */
    public String authenticateWithClientAssertion(
            String clientAssertion,
            String clientAssertionType,
            Map<String, String> requestBody,
            OAuth2ClientStore clientStore) {

        // Validate assertion type
        if (!JWT_BEARER_ASSERTION_TYPE.equals(clientAssertionType)) {
            logger.error("Unsupported client_assertion_type: {}", clientAssertionType);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Unsupported client_assertion_type: " + clientAssertionType);
        }

        // Parse the JWT assertion
        logger.debug("Parsing client assertion JWT...");
        SignedJWT signedJwt;
        JWTClaimsSet claimsSet;
        try {
            signedJwt = SignedJWT.parse(clientAssertion);
            claimsSet = signedJwt.getJWTClaimsSet();
        } catch (Exception e) {
            logger.error("Failed to parse client assertion JWT", e);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Invalid client assertion JWT");
        }

        // Resolve client_id: prefer request body parameter, fall back to JWT iss claim
        // In WIMSE scenarios, the client_id in the request body is the workload identity
        // (e.g., wimse://trust.domain/workload/UUID), which was assigned during DCR.
        // The JWT iss claim is the trust domain (e.g., wimse://trust.domain), not the client_id.
        String requestBodyClientId = requestBody != null ? requestBody.get("client_id") : null;
        String jwtIssuer = claimsSet.getIssuer();
        String jwtSubject = claimsSet.getSubject();

        // Resolve client_id: prefer request body parameter, fall back to JWT iss claim.
        // In WIMSE scenarios, the client_id in the request body is the workload identity
        // (e.g., wimse://trust.domain/workload/UUID) assigned during DCR, which also
        // matches the JWT sub claim.
        String clientId;
        if (!ValidationUtils.isNullOrEmpty(requestBodyClientId)) {
            clientId = requestBodyClientId;
            logger.debug("Using client_id from request body: {}", clientId);

            // Validate that JWT sub matches the request body client_id.
            // In WIMSE, DCR assigns WIT.sub as client_id, so sub must equal client_id.
            if (!clientId.equals(jwtSubject)) {
                logger.error("Client assertion JWT 'sub' claim ({}) does not match request body 'client_id' ({})",
                        jwtSubject, clientId);
                throw FrameworkOAuth2TokenException.invalidClient(
                        "Client authentication failed: Client assertion JWT 'sub' must match 'client_id'");
            }
        } else if (!ValidationUtils.isNullOrEmpty(jwtIssuer)) {
            clientId = jwtIssuer;
            logger.debug("Using client_id from JWT 'iss' claim: {}", clientId);

            // In standard RFC 7523 mode, sub must match iss per Section 3
            if (!clientId.equals(jwtSubject)) {
                logger.error("Client assertion JWT 'sub' claim ({}) does not match 'iss' claim ({})",
                        jwtSubject, clientId);
                throw FrameworkOAuth2TokenException.invalidClient(
                        "Client authentication failed: Client assertion JWT 'sub' must match 'iss'");
            }
        } else {
            logger.error("No client_id in request body and no 'iss' claim in JWT");
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Unable to determine client_id");
        }

        logger.debug("Client assertion JWT claims - iss: {}, sub: {}, resolved client_id: {}", jwtIssuer, jwtSubject, clientId);

        // Validate expiration
        Date expirationTime = claimsSet.getExpirationTime();
        if (expirationTime == null || expirationTime.before(new Date())) {
            logger.error("Client assertion JWT is expired for client: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client assertion JWT is expired");
        }
        logger.debug("Client assertion JWT claims validated - client_id: {}, exp: {}", clientId, expirationTime);

        // Retrieve client from store
        OAuth2RegisteredClient client = clientStore.retrieve(clientId);
        if (client == null) {
            logger.error("Client not found: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client not registered");
        }
        logger.debug("Client '{}' found in store, auth_method: {}", clientId, client.getTokenEndpointAuthMethod());

        // Validate auth method
        String authMethod = client.getTokenEndpointAuthMethod();
        if (authMethod != null && !PRIVATE_KEY_JWT.equals(authMethod)) {
            logger.error("Client {} is not configured for private_key_jwt, configured method: {}", clientId, authMethod);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client is not configured for private_key_jwt authentication");
        }

        // Verify JWT signature
        logger.debug("Verifying client assertion JWT signature for client: {}", clientId);
        verifyClientAssertionSignature(signedJwt, client);

        logger.info("Client authenticated via private_key_jwt: {}", clientId);
        return clientId;
    }

    /**
     * Verifies the JWT signature using client's registered jwks first, falling back to KeyManager.
     * <p>
     * This method implements a two-tier verification strategy:
     * </p>
     * <ol>
     *   <li><b>Priority 1: Client's registered jwks</b> - If the client has inline jwks
     *       registered during DCR, use those keys to verify the signature. This is the
     *       standard Software Statement + private_key_jwt flow.</li>
     *   <li><b>Priority 2: KeyManager infrastructure</b> - If no inline jwks, fall back
     *       to the {@link KeyManager} infrastructure for key resolution. This ensures
     *       backward compatibility with existing deployments.</li>
     * </ol>
     * <p>
     * When using inline jwks:
     * </p>
     * <ul>
     *   <li>Parse the jwks Map into a JWKSet</li>
     *   <li>Match JWK by kid from JWT header, or use first key if no kid</li>
     *   <li>Create appropriate verifier based on key type (EC or RSA)</li>
     *   <li>Verify signature</li>
     * </ul>
     *
     * @param signedJwt the signed JWT to verify
     * @param client the registered client
     * @throws FrameworkOAuth2TokenException if signature verification fails
     */
    private void verifyClientAssertionSignature(SignedJWT signedJwt, OAuth2RegisteredClient client) {

        String headerKeyId = signedJwt.getHeader().getKeyID();
        String algorithm = signedJwt.getHeader().getAlgorithm().getName();
        String clientId = client.getClientId();

        logger.debug("Verifying client assertion signature for client '{}' - header kid: {}, algorithm: {}",
                clientId, headerKeyId, algorithm);

        // Priority 1: Try to use client's registered inline jwks
        Map<String, Object> inlineJwks = client.getJwks();
        if (inlineJwks != null && !inlineJwks.isEmpty()) {
            logger.debug("Client '{}' has inline jwks, using them for signature verification", clientId);
            try {
                verifyWithInlineJwks(signedJwt, inlineJwks, clientId);
                logger.debug("Client assertion signature verified successfully using inline jwks for client: {}", clientId);
                return;
            } catch (Exception e) {
                logger.error("Failed to verify signature using inline jwks for client: {}", clientId, e);
                throw FrameworkOAuth2TokenException.invalidClient(
                        "Client authentication failed: Signature verification using inline jwks failed - " + e.getMessage());
            }
        }

        // Priority 2: Fall back to KeyManager infrastructure
        logger.debug("Client '{}' has no inline jwks, falling back to KeyManager for signature verification", clientId);
        logger.debug("Using KeyManager - verificationKeyId: {}", verificationKeyId);

        boolean isValid = SignatureVerificationUtils.verifySignature(signedJwt, keyManager, verificationKeyId);

        if (!isValid) {
            logger.error("Client assertion JWT signature verification failed for client: {}", clientId);
            throw FrameworkOAuth2TokenException.invalidClient(
                    "Client authentication failed: Client assertion JWT signature verification failed");
        }

        logger.debug("Client assertion JWT signature verified successfully using KeyManager for client: {}", clientId);
    }

    /**
     * Verifies the JWT signature using the client's inline jwks.
     * <p>
     * This method parses the inline jwks from the client registration and uses them
     * to verify the JWT signature. It supports both EC and RSA keys.
     * </p>
     *
     * @param signedJwt the signed JWT to verify
     * @param inlineJwks the inline jwks from client registration
     * @param clientId the client ID for logging
     * @throws Exception if verification fails
     */
    private void verifyWithInlineJwks(SignedJWT signedJwt, Map<String, Object> inlineJwks, String clientId) throws Exception {

        // Parse jwks Map to JSON string
        ObjectMapper objectMapper = new ObjectMapper();
        String jwksJson = objectMapper.writeValueAsString(inlineJwks);

        // Parse JWKSet
        JWKSet jwkSet = JWKSet.parse(jwksJson);

        // Get the key to use for verification
        JWK verificationKey = JwkUtils.selectVerificationKey(jwkSet, signedJwt.getHeader().getKeyID());

        // Create appropriate verifier based on key type
        JWSVerifier verifier = SignatureVerificationUtils.createVerifier(verificationKey);

        // Verify signature
        boolean isValid = signedJwt.verify(verifier);
        if (!isValid) {
            throw new Exception("Signature verification failed");
        }

        logger.debug("Signature verified successfully using inline jwk - kid: {}, kty: {}",
                verificationKey.getKeyID(), verificationKey.getKeyType());
    }

}