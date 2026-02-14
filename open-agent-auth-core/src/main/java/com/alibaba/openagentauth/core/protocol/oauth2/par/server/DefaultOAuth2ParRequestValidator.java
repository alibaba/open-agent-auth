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
package com.alibaba.openagentauth.core.protocol.oauth2.par.server;

import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.core.model.oauth2.par.ParRequest;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link OAuth2ParRequestValidator}.
 * <p>
 * This implementation provides standard OAuth 2.0 parameter validation
 * according to RFC 9126 specification. It validates:
 * </p>
 * <ul>
 *   <li>response_type parameter</li>
 *   <li>client_id parameter</li>
 *   <li>redirect_uri parameter</li>
 *   <li>request JWT basic format (header.payload.signature)</li>
 * </ul>
 * <p>
 * <b>Note:</b> This validator only performs basic JWT format validation.
 * For comprehensive JWT signature verification and claims validation,
 * use a specialized JWT validator before calling this validator.
 * </p>
 * <p>
 * <b>Separation of Concerns:</b></p>
 * <ul>
 *   <li><b>Standard PAR validation:</b> Handled by this validator</li>
 *   <li><b>AAP-specific JWT validation:</b> Handled by {@code AapParJwtValidator}
 *       before delegating to ParServer</li>
 * </ul>
 *
 * @since 1.0
 */
public class DefaultOAuth2ParRequestValidator implements OAuth2ParRequestValidator {

    private static final Logger logger = LoggerFactory.getLogger(DefaultOAuth2ParRequestValidator.class);

    /**
     * Creates a new validator.
     */
    public DefaultOAuth2ParRequestValidator() {
        // No dependencies needed for standard PAR validation
    }

    @Override
    public void validate(ParRequest request) {
        ValidationUtils.validateNotNull(request, "PAR request");

        logger.debug("Validating PAR request for client: {}", request.getClientId());

        // Validate OAuth 2.0 parameters
        validateResponseType(request);
        validateClientId(request);
        validateRedirectUri(request);
        validateRequestJwt(request);
        
        logger.debug("PAR request validation successful");
    }

    /**
     * Validates the response_type parameter.
     */
    private void validateResponseType(ParRequest request) {
        String responseType = request.getResponseType();

        if (ValidationUtils.isNullOrEmpty(responseType)) {
            throw ParException.missingParameter("response_type");
        }

        if (!responseType.equals("code")) {
            logger.warn("Unsupported response_type: {}", responseType);
            throw ParException.invalidParameter("response_type", "Only 'code' response_type is supported");
        }
    }

    /**
     * Validates the client_id parameter.
     */
    private void validateClientId(ParRequest request) {
        String clientId = request.getClientId();

        if (ValidationUtils.isNullOrEmpty(clientId)) {
            throw ParException.missingParameter("client_id");
        }
    }

    /**
     * Validates the redirect_uri parameter.
     */
    private void validateRedirectUri(ParRequest request) {
        String redirectUri = request.getRedirectUri();

        if (ValidationUtils.isNullOrEmpty(redirectUri)) {
            throw ParException.missingParameter("redirect_uri");
        }

        // Basic URI format validation
        try {
            new java.net.URI(redirectUri);
        } catch (Exception e) {
            throw ParException.invalidRedirectUri("redirect_uri must be a valid URI");
        }
    }

    /**
     * Validates the request JWT.
     * <p>
     * Performs basic JWT format validation (header.payload.signature structure).
     * </p>
     * <p>
     * <b>Note:</b> This method only validates the JWT format, not the signature
     * or claims. Signature verification should be performed by a specialized
     * JWT validator before calling the standard PAR validator.
     * </p>
     */
    private void validateRequestJwt(ParRequest request) {
        String requestJwt = request.getRequestJwt();

        if (ValidationUtils.isNullOrEmpty(requestJwt)) {
            throw ParException.missingParameter("request");
        }

        // Basic JWT format validation (header.payload.signature)
        String[] parts = requestJwt.split("\\.");
        if (parts.length != 3) {
            throw ParException.invalidParameter("request", "request must be a valid JWT with header, payload, and signature");
        }

        logger.debug("Request JWT format validation passed");
    }
}