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
package com.alibaba.openagentauth.core.token.common;

/**
 * Generic result class for token validation.
 * Represents the outcome of validating a token (WIT, WPT, etc.).
 *
 * @param <T> the type of token being validated
 */
public class TokenValidationResult<T> {

    /**
     * Indicates whether the token is valid.
     */
    private final boolean valid;

    /**
     * Error message if the token is invalid.
     */
    private final String errorMessage;

    /**
     * Parsed token if the token is valid.
     */
    private final T token;

    /**
     * Constructor.
     *
     * @param valid indicates whether the token is valid
     * @param errorMessage error message if the token is invalid
     * @param token parsed token if the token is valid
     */
    private TokenValidationResult(boolean valid, String errorMessage, T token) {
        this.valid = valid;
        this.errorMessage = errorMessage;
        this.token = token;
    }

    /**
     * Returns true if the token is valid, false otherwise.
     *
     * @return true if the token is valid, false otherwise
     */
    public boolean isValid() {
        return valid;
    }

    /**
     * Returns the error message if the token is invalid.
     *
     * @return the error message if the token is invalid
     */
    public String getErrorMessage() {
        return errorMessage;
    }

    /**
     * Returns the parsed token if the token is valid.
     *
     * @return the parsed token if the token is valid
     */
    public T getToken() {
        return token;
    }

    /**
     * Creates a successful validation result.
     *
     * @param token the parsed token
     * @param <T> the type of token
     * @return the validation result
     */
    public static <T> TokenValidationResult<T> success(T token) {
        return new TokenValidationResult<>(true, null, token);
    }

    /**
     * Creates a failed validation result.
     *
     * @param errorMessage the error message
     * @param <T> the type of token
     * @return the validation result
     */
    public static <T> TokenValidationResult<T> failure(String errorMessage) {
        return new TokenValidationResult<>(false, errorMessage, null);
    }
}
