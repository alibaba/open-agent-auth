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
package com.alibaba.openagentauth.spring.web.model;

import com.alibaba.openagentauth.core.exception.oauth2.DcrException;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2Exception;
import com.alibaba.openagentauth.core.exception.oauth2.OAuth2RfcErrorCode;
import com.alibaba.openagentauth.core.exception.oauth2.ParException;
import com.alibaba.openagentauth.framework.exception.oauth2.FrameworkOAuth2TokenException;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * Standard OAuth 2.0 error response model per RFC 6749 Section 5.2.
 * <p>
 * This class provides a type-safe representation of OAuth 2.0 error responses,
 * ensuring all error responses conform to the standard format defined in:
 * </p>
 * <ul>
 *   <li><b>RFC 6749 Section 4.1.2.1</b> - Authorization Error Response</li>
 *   <li><b>RFC 6749 Section 5.2</b> - Token Error Response</li>
 *   <li><b>RFC 7591 Section 3.2.2</b> - DCR Error Response</li>
 *   <li><b>RFC 9126 Section 2.3</b> - PAR Error Response</li>
 * </ul>
 * <p>
 * <b>Standard Error Response Format:</b>
 * </p>
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json
 *
 * {
 *   "error": "invalid_request",
 *   "error_description": "The request is missing a required parameter"
 * }
 * </pre>
 * <p>
 * <b>Design Principles:</b>
 * </p>
 * <ul>
 *   <li>Immutable value object (thread-safe)</li>
 *   <li>Factory methods for common error scenarios</li>
 *   <li>Automatic RFC error code extraction from framework exceptions</li>
 *   <li>Consistent HTTP status code mapping per RFC specifications</li>
 * </ul>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.2">RFC 6749 - Error Response</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2">RFC 7591 - DCR Error Response</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public final class OAuth2ErrorResponse {

    /**
     * The error code as defined by the relevant RFC specification.
     * <p>
     * This MUST be a single ASCII error code string from the applicable RFC,
     * such as {@code invalid_request}, {@code invalid_client}, {@code invalid_grant}, etc.
     * </p>
     */
    @JsonProperty("error")
    private final String error;

    /**
     * A human-readable description providing additional information about the error.
     * <p>
     * Per RFC 6749 Section 5.2, this is OPTIONAL and intended to assist the client
     * developer in understanding the error. It is NOT meant to be displayed to the end user.
     * </p>
     */
    @JsonProperty("error_description")
    private final String errorDescription;

    /**
     * The HTTP status code for this error response.
     * <p>
     * This field is not serialized to JSON; it is used internally to determine
     * the HTTP response status code.
     * </p>
     */
    private final transient int httpStatus;

    private OAuth2ErrorResponse(String error, String errorDescription, int httpStatus) {
        this.error = error;
        this.errorDescription = errorDescription;
        this.httpStatus = httpStatus;
    }

    // ============ Factory Methods from Exceptions ============

    /**
     * Creates an error response from a core {@link OAuth2Exception}.
     * <p>
     * Extracts the RFC error code via {@link OAuth2Exception#getRfcErrorCode()}.
     * If no RFC error code is available, falls back to {@code server_error}.
     * </p>
     *
     * @param exception the OAuth2 exception
     * @return the error response with RFC-compliant error code
     */
    public static OAuth2ErrorResponse fromOAuth2Exception(OAuth2Exception exception) {
        String rfcError = exception.getRfcErrorCode();
        if (rfcError == null || rfcError.isBlank()) {
            rfcError = OAuth2RfcErrorCode.SERVER_ERROR.getValue();
        }
        int status = determineHttpStatus(rfcError);

        if (exception instanceof DcrException dcrException) {
            status = dcrException.getStatusCode();
        } else if (exception instanceof ParException parException) {
            status = parException.getStatusCode();
        }

        return new OAuth2ErrorResponse(rfcError, exception.getMessage(), status);
    }

    /**
     * Creates an error response from a {@link FrameworkOAuth2TokenException}.
     * <p>
     * The framework exception already carries RFC-compliant error codes
     * (e.g., {@code invalid_client}, {@code invalid_grant}).
     * </p>
     *
     * @param exception the framework OAuth2 token exception
     * @return the error response
     */
    public static OAuth2ErrorResponse fromFrameworkException(FrameworkOAuth2TokenException exception) {
        return new OAuth2ErrorResponse(
                exception.getErrorCode(),
                exception.getErrorDescription(),
                exception.getHttpStatus()
        );
    }

    // ============ Factory Methods for Standard Errors ============

    /**
     * Creates an {@code invalid_request} error response (HTTP 400).
     *
     * @param description the error description
     * @return the error response
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-5.2">RFC 6749 Section 5.2</a>
     */
    public static OAuth2ErrorResponse invalidRequest(String description) {
        return new OAuth2ErrorResponse(
                OAuth2RfcErrorCode.INVALID_REQUEST.getValue(),
                description,
                HttpStatus.BAD_REQUEST.value()
        );
    }

    /**
     * Creates a {@code server_error} error response (HTTP 500).
     *
     * @param description the error description
     * @return the error response
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1">RFC 6749 Section 4.1.2.1</a>
     */
    public static OAuth2ErrorResponse serverError(String description) {
        return new OAuth2ErrorResponse(
                OAuth2RfcErrorCode.SERVER_ERROR.getValue(),
                description,
                HttpStatus.INTERNAL_SERVER_ERROR.value()
        );
    }

    /**
     * Creates a custom error response with the specified error code, description, and HTTP status.
     *
     * @param error the RFC error code
     * @param description the error description
     * @param httpStatus the HTTP status code
     * @return the error response
     */
    public static OAuth2ErrorResponse of(String error, String description, int httpStatus) {
        return new OAuth2ErrorResponse(error, description, httpStatus);
    }

    // ============ Response Conversion ============

    /**
     * Converts this error response to a Spring {@link ResponseEntity}.
     * <p>
     * The response body contains only the {@code error} and {@code error_description}
     * fields as required by the OAuth 2.0 specification.
     * </p>
     *
     * @return the response entity with appropriate HTTP status and error body
     */
    public ResponseEntity<OAuth2ErrorResponse> toResponseEntity() {
        return ResponseEntity.status(httpStatus).body(this);
    }

    // ============ Getters ============

    /**
     * Gets the RFC error code.
     *
     * @return the error code (e.g., {@code invalid_request})
     */
    public String getError() {
        return error;
    }

    /**
     * Gets the error description.
     *
     * @return the error description
     */
    public String getErrorDescription() {
        return errorDescription;
    }

    /**
     * Gets the HTTP status code.
     *
     * @return the HTTP status code
     */
    public int getHttpStatus() {
        return httpStatus;
    }

    // ============ Internal Helpers ============

    /**
     * Determines the appropriate HTTP status code based on the RFC error code.
     * <p>
     * Mapping follows RFC 6749 and RFC 6750 conventions:
     * </p>
     * <ul>
     *   <li>{@code invalid_client} → 401 (Unauthorized)</li>
     *   <li>{@code unauthorized_client} → 403 (Forbidden)</li>
     *   <li>{@code access_denied} → 403 (Forbidden)</li>
     *   <li>{@code server_error} → 500 (Internal Server Error)</li>
     *   <li>{@code temporarily_unavailable} → 503 (Service Unavailable)</li>
     *   <li>All other errors → 400 (Bad Request)</li>
     * </ul>
     *
     * @param rfcErrorCode the RFC error code string
     * @return the HTTP status code
     */
    private static int determineHttpStatus(String rfcErrorCode) {
        if (rfcErrorCode == null) {
            return HttpStatus.INTERNAL_SERVER_ERROR.value();
        }
        return switch (rfcErrorCode) {
            case "invalid_client" -> HttpStatus.UNAUTHORIZED.value();
            case "unauthorized_client", "access_denied" -> HttpStatus.FORBIDDEN.value();
            case "server_error" -> HttpStatus.INTERNAL_SERVER_ERROR.value();
            case "temporarily_unavailable" -> HttpStatus.SERVICE_UNAVAILABLE.value();
            default -> HttpStatus.BAD_REQUEST.value();
        };
    }

    @Override
    public String toString() {
        return "OAuth2ErrorResponse{" +
                "error='" + error + '\'' +
                ", errorDescription='" + errorDescription + '\'' +
                ", httpStatus=" + httpStatus +
                '}';
    }
}
