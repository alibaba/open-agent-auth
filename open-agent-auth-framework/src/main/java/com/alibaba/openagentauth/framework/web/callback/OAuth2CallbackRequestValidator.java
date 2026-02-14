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
package com.alibaba.openagentauth.framework.web.callback;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import java.util.Map;

/**
 * OAuth2 callback request validator.
 * <p>
 * Validates callback request parameters to ensure request validity.
 * </p>
 *
 * @since 1.0
 */
public class OAuth2CallbackRequestValidator {
    
    /**
     * Validate callback request.
     *
     * @param request callback request
     * @param clientId client ID (used for configuration validation)
     * @return validation result
     */
    public ValidationResult validate(OAuth2CallbackRequest request, String clientId) {
        // Handle error response
        if (request.hasError()) {
            return ValidationResult.error(
                "invalid_request",
                request.getErrorDescription() != null ? request.getErrorDescription() : "Authorization failed",
                400
            );
        }
        
        // Validate authorization code
        if (ValidationUtils.isNullOrEmpty(request.getCode())) {
            return ValidationResult.error(
                "invalid_request",
                "Missing authorization code",
                400
            );
        }
        
        // Validate client configuration
        if (ValidationUtils.isNullOrEmpty(clientId)) {
            return ValidationResult.error(
                "server_error",
                "Client ID not configured",
                500
            );
        }
        
        return ValidationResult.success();
    }
    
    /**
     * Validation result.
     */
    public static class ValidationResult {
        private final boolean success;
        private final String error;
        private final String errorDescription;
        private final int statusCode;
        
        private ValidationResult(boolean success, String error, 
                               String errorDescription, int statusCode) {
            this.success = success;
            this.error = error;
            this.errorDescription = errorDescription;
            this.statusCode = statusCode;
        }
        
        public static ValidationResult success() {
            return new ValidationResult(true, null, null, 200);
        }
        
        public static ValidationResult error(String error, String errorDescription, int statusCode) {
            return new ValidationResult(false, error, errorDescription, statusCode);
        }
        
        public boolean isSuccess() {
            return success;
        }
        
        public String getError() {
            return error;
        }
        
        public String getErrorDescription() {
            return errorDescription;
        }
        
        public int getStatusCode() {
            return statusCode;
        }
        
        /**
         * Convert to error response Map.
         *
         * @return error response Map
         */
        public Map<String, String> toErrorResponseMap() {
            if (success) {
                return Map.of();
            }
            return Map.of(
                "error", error,
                "error_description", errorDescription != null ? errorDescription : "Authorization failed"
            );
        }
    }
}