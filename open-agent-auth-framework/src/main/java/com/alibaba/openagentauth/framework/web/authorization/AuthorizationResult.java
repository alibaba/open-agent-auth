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
package com.alibaba.openagentauth.framework.web.authorization;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import java.util.Objects;

/**
 * Result object for authorization flow processing.
 * <p>
 * This class encapsulates the result of authorization processing, providing
 * a type-safe way to return different types of results (redirect, error, or consent page)
 * without depending on Spring's HTTP response classes.
 * </p>
 * <p>
 * <b>Design Principles:</b></p>
 * <ul>
 *   <li><b>Immutable:</b> All fields are final, ensuring thread safety</li>
 *   <li><b>Factory Methods:</b> Provides convenient factory methods for creating different result types</li>
 *   <li><b>Type Safety:</b> Uses enum to distinguish result types, avoiding string-based type checking</li>
 *   <li><b>Separation of Concerns:</b> Decouples business logic from HTTP response handling</li>
 * </ul>
 *
 * @since 1.0
 */
public class AuthorizationResult {

    /**
     * The type of authorization result.
     */
    public enum ResultType {
        /**
         * Redirect to a URI (typically client callback or login page).
         */
        REDIRECT,
        /**
         * Error response with OAuth 2.0 error parameters.
         */
        ERROR,
        /**
         * Render a consent page.
         */
        CONSENT_PAGE
    }

    private final ResultType type;
    private final String redirectUri;
    private final Object consentPage;
    private final String error;
    private final String errorDescription;
    private final int httpStatus;

    private AuthorizationResult(ResultType type, String redirectUri, Object consentPage, 
                               String error, String errorDescription, int httpStatus) {
        this.type = ValidationUtils.validateNotNull(type, "type");
        this.redirectUri = redirectUri;
        this.consentPage = consentPage;
        this.error = error;
        this.errorDescription = errorDescription;
        this.httpStatus = httpStatus;
    }

    /**
     * Creates a redirect result.
     *
     * @param redirectUri the URI to redirect to (must not be null or blank)
     * @return a redirect result
     * @throws IllegalArgumentException if redirectUri is null or blank
     */
    public static AuthorizationResult redirect(String redirectUri) {
        ValidationUtils.validateNotEmpty(redirectUri, "redirectUri");
        return new AuthorizationResult(ResultType.REDIRECT, redirectUri, null, null, null, 0);
    }

    /**
     * Creates an error result with HTTP status 400.
     *
     * @param error the OAuth 2.0 error code (e.g., "invalid_request")
     * @param errorDescription the error description (can be null)
     * @return an error result
     * @throws IllegalArgumentException if error is null or blank
     */
    public static AuthorizationResult error(String error, String errorDescription) {
        ValidationUtils.validateNotEmpty(error, "error");
        return new AuthorizationResult(ResultType.ERROR, null, null, error, errorDescription, 400);
    }

    /**
     * Creates an error result with a custom HTTP status.
     *
     * @param error the OAuth 2.0 error code (e.g., "invalid_request")
     * @param errorDescription the error description (can be null)
     * @param httpStatus the HTTP status code
     * @return an error result
     * @throws IllegalArgumentException if error is null or blank
     */
    public static AuthorizationResult error(String error, String errorDescription, int httpStatus) {
        ValidationUtils.validateNotEmpty(error, "error");
        return new AuthorizationResult(ResultType.ERROR, null, null, error, errorDescription, httpStatus);
    }

    /**
     * Creates an unauthorized error result with HTTP status 401.
     *
     * @param error the OAuth 2.0 error code (e.g., "login_required")
     * @param errorDescription the error description (can be null)
     * @return an unauthorized error result
     * @throws IllegalArgumentException if error is null or blank
     */
    public static AuthorizationResult unauthorized(String error, String errorDescription) {
        return error(error, errorDescription, 401);
    }

    /**
     * Creates a consent page result.
     *
     * @param consentPage the consent page object (typically a ModelAndView or similar)
     * @return a consent page result
     * @throws IllegalArgumentException if consentPage is null
     */
    public static AuthorizationResult consentPage(Object consentPage) {
        ValidationUtils.validateNotNull(consentPage, "consentPage");
        return new AuthorizationResult(ResultType.CONSENT_PAGE, null, consentPage, null, null, 0);
    }

    /**
     * Gets the result type.
     *
     * @return the result type
     */
    public ResultType getType() {
        return type;
    }

    /**
     * Gets the redirect URI.
     *
     * @return the redirect URI, or null if this is not a redirect result
     */
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Gets the consent page object.
     *
     * @return the consent page object, or null if this is not a consent page result
     */
    public Object getConsentPage() {
        return consentPage;
    }

    /**
     * Gets the OAuth 2.0 error code.
     *
     * @return the error code, or null if this is not an error result
     */
    public String getError() {
        return error;
    }

    /**
     * Gets the error description.
     *
     * @return the error description, or null if this is not an error result
     */
    public String getErrorDescription() {
        return errorDescription;
    }

    /**
     * Gets the HTTP status code.
     *
     * @return the HTTP status code, or 0 if this is not an error result
     */
    public int getHttpStatus() {
        return httpStatus;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthorizationResult that = (AuthorizationResult) o;
        return httpStatus == that.httpStatus &&
                type == that.type &&
                Objects.equals(redirectUri, that.redirectUri) &&
                Objects.equals(consentPage, that.consentPage) &&
                Objects.equals(error, that.error) &&
                Objects.equals(errorDescription, that.errorDescription);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, redirectUri, consentPage, error, errorDescription, httpStatus);
    }

    @Override
    public String toString() {
        return "AuthorizationResult{" +
                "type=" + type +
                ", redirectUri='" + redirectUri + '\'' +
                ", consentPage=" + consentPage +
                ", error='" + error + '\'' +
                ", errorDescription='" + errorDescription + '\'' +
                ", httpStatus=" + httpStatus +
                '}';
    }
}
