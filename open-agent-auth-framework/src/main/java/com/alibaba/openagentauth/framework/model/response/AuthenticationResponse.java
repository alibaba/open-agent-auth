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
package com.alibaba.openagentauth.framework.model.response;

import java.util.Map;

/**
 * Authentication response containing the authentication result and issued tokens.
 * <p>
 * This class encapsulates the response from a successful authentication,
 * including the ID Token and optional additional information.
 * </p>
 */
public class AuthenticationResponse {
    
    private final boolean success;
    private final String idToken;
    private final String tokenType;
    private final long expiresIn;
    private final String refreshToken;
    private final Map<String, Object> additionalInfo;
    
    private AuthenticationResponse(Builder builder) {
        this.success = builder.success;
        this.idToken = builder.idToken;
        this.tokenType = builder.tokenType;
        this.expiresIn = builder.expiresIn;
        this.refreshToken = builder.refreshToken;
        this.additionalInfo = Map.copyOf(builder.additionalInfo);
    }
    
    /**
     * Checks if authentication was successful.
     *
     * @return true if successful
     */
    public boolean isSuccess() {
        return success;
    }
    
    /**
     * Gets the ID Token.
     *
     * @return the ID Token
     */
    public String getIdToken() {
        return idToken;
    }
    
    /**
     * Gets the token type (typically "Bearer").
     *
     * @return the token type
     */
    public String getTokenType() {
        return tokenType;
    }
    
    /**
     * Gets the token expiration time in seconds.
     *
     * @return the expiration time
     */
    public long getExpiresIn() {
        return expiresIn;
    }
    
    /**
     * Gets the refresh token (optional).
     *
     * @return the refresh token, or null if not available
     */
    public String getRefreshToken() {
        return refreshToken;
    }
    
    /**
     * Gets additional information.
     *
     * @return the additional info map
     */
    public Map<String, Object> getAdditionalInfo() {
        return additionalInfo;
    }
    
    /**
     * Creates a new builder for AuthenticationResponse.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for AuthenticationResponse.
     */
    public static class Builder {
        private boolean success = false;
        private String idToken;
        private String tokenType = "Bearer";
        private long expiresIn = 3600;
        private String refreshToken;
        private final Map<String, Object> additionalInfo = new java.util.HashMap<>();
        
        /**
         * Sets the success flag.
         *
         * @param success the success flag
         * @return this builder instance
         */
        public Builder success(boolean success) {
            this.success = success;
            return this;
        }
        
        /**
         * Sets the ID Token.
         *
         * @param idToken the ID Token
         * @return this builder instance
         */
        public Builder idToken(String idToken) {
            this.idToken = idToken;
            return this;
        }
        
        /**
         * Sets the token type.
         *
         * @param tokenType the token type
         * @return this builder instance
         */
        public Builder tokenType(String tokenType) {
            this.tokenType = tokenType;
            return this;
        }
        
        /**
         * Sets the expiration time.
         *
         * @param expiresIn the expiration time in seconds
         * @return this builder instance
         */
        public Builder expiresIn(long expiresIn) {
            this.expiresIn = expiresIn;
            return this;
        }
        
        /**
         * Sets the refresh token.
         *
         * @param refreshToken the refresh token
         * @return this builder instance
         */
        public Builder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }
        
        /**
         * Adds additional information.
         *
         * @param key the key
         * @param value the value
         * @return this builder instance
         */
        public Builder addInfo(String key, Object value) {
            this.additionalInfo.put(key, value);
            return this;
        }
        
        /**
         * Builds the AuthenticationResponse.
         *
         * @return the built response
         */
        public AuthenticationResponse build() {
            return new AuthenticationResponse(this);
        }
    }
}
