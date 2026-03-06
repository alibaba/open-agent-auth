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
package com.alibaba.openagentauth.spring.web.controller;

import com.alibaba.openagentauth.core.exception.oauth2.OAuth2Exception;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.alibaba.openagentauth.spring.web.model.OAuth2ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Global exception handler for OAuth 2.0 protocol errors.
 * <p>
 * This handler intercepts OAuth 2.0 related exceptions thrown by controllers and
 * converts them into RFC-compliant error responses. It ensures that all OAuth 2.0
 * endpoints return consistent, standard-compliant error responses as defined in:
 * </p>
 * <ul>
 *   <li><b>RFC 6749 Section 5.2</b> - Token Error Response</li>
 *   <li><b>RFC 6749 Section 4.1.2.1</b> - Authorization Error Response</li>
 *   <li><b>RFC 7591 Section 3.2.2</b> - DCR Error Response</li>
 *   <li><b>RFC 9126 Section 2.3</b> - PAR Error Response</li>
 * </ul>
 * <p>
 * <b>Design Pattern:</b> Chain of Responsibility (Spring's exception handler chain)
 * </p>
 * <p>
 * <b>Key Behavior:</b>
 * </p>
 * <ul>
 *   <li>Extracts RFC error codes from exceptions (not internal IDEM error codes)</li>
 *   <li>Maps error codes to appropriate HTTP status codes per RFC specifications</li>
 *   <li>Returns JSON error responses with {@code error} and {@code error_description} fields</li>
 *   <li>Logs errors at appropriate levels for debugging</li>
 * </ul>
 *
 * @see OAuth2ErrorResponse
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.2">RFC 6749 - Error Response</a>
 * @since 1.0
 */
@RestControllerAdvice(assignableTypes = {
        OAuth2TokenController.class,
        OAuth2AuthorizationController.class,
        OAuth2DcrController.class,
        OAuth2ParController.class,
        TokenRevocationController.class,
        OidcUserInfoController.class,
        OAuth2CallbackController.class
})
public class OAuth2ExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2ExceptionHandler.class);

    /**
     * Handles core {@link OAuth2Exception} and its subclasses.
     * <p>
     * This covers all protocol-level OAuth 2.0 exceptions including:
     * {@code OAuth2TokenException}, {@code OAuth2AuthorizationException},
     * {@code DcrException}, {@code ParException}, and {@code ClientAssertionException}.
     * </p>
     * <p>
     * The RFC error code is extracted via {@link OAuth2Exception#getRfcErrorCode()},
     * ensuring the response uses standard OAuth 2.0 error codes (e.g., {@code invalid_request})
     * rather than internal framework error codes.
     * </p>
     *
     * @param exception the OAuth2 exception
     * @return the RFC-compliant error response
     */
    @ExceptionHandler(OAuth2Exception.class)
    public ResponseEntity<OAuth2ErrorResponse> handleOAuth2Exception(OAuth2Exception exception) {
        OAuth2ErrorResponse errorResponse = OAuth2ErrorResponse.fromOAuth2Exception(exception);
        logger.error("OAuth2 protocol error [{}]: {}", errorResponse.getError(), exception.getMessage(), exception);
        return errorResponse.toResponseEntity();
    }

    /**
     * Handles {@link FrameworkOAuth2TokenException} from the framework layer.
     * <p>
     * This exception is thrown by the framework's token processing pipeline
     * (e.g., client authentication, token exchange). It already carries
     * RFC-compliant error codes.
     * </p>
     *
     * @param exception the framework OAuth2 token exception
     * @return the RFC-compliant error response
     */
    @ExceptionHandler(FrameworkOAuth2TokenException.class)
    public ResponseEntity<OAuth2ErrorResponse> handleFrameworkOAuth2TokenException(
            FrameworkOAuth2TokenException exception) {
        OAuth2ErrorResponse errorResponse = OAuth2ErrorResponse.fromFrameworkException(exception);
        logger.error("Framework OAuth2 error [{}]: {}", errorResponse.getError(), exception.getMessage(), exception);
        return errorResponse.toResponseEntity();
    }

    /**
     * Handles {@link IllegalArgumentException} as {@code invalid_request} errors.
     * <p>
     * In OAuth 2.0 contexts, {@code IllegalArgumentException} typically indicates
     * a malformed or invalid request parameter, which maps to the standard
     * {@code invalid_request} error code per RFC 6749.
     * </p>
     *
     * @param exception the illegal argument exception
     * @return the RFC-compliant error response with {@code invalid_request} error code
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<OAuth2ErrorResponse> handleIllegalArgumentException(
            IllegalArgumentException exception) {
        OAuth2ErrorResponse errorResponse = OAuth2ErrorResponse.invalidRequest(exception.getMessage());
        logger.error("Invalid request: {}", exception.getMessage(), exception);
        return errorResponse.toResponseEntity();
    }

    /**
     * Handles unexpected exceptions as {@code server_error}.
     * <p>
     * Per RFC 6749 Section 4.1.2.1, the {@code server_error} code indicates that
     * the authorization server encountered an unexpected condition that prevented
     * it from fulfilling the request.
     * </p>
     *
     * @param exception the unexpected exception
     * @return the RFC-compliant error response with {@code server_error} error code
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<OAuth2ErrorResponse> handleUnexpectedException(Exception exception) {
        OAuth2ErrorResponse errorResponse = OAuth2ErrorResponse.serverError("Internal server error");
        logger.error("Unexpected error in OAuth2 endpoint: {}", exception.getMessage(), exception);
        return errorResponse.toResponseEntity();
    }
}
