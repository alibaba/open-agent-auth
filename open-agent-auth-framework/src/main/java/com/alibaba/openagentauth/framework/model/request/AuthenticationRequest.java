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
package com.alibaba.openagentauth.framework.model.request;

import java.util.Map;

/**
 * Authentication request containing user credentials and authentication context.
 * <p>
 * This class encapsulates all information needed for user authentication,
 * including credentials (username/password, OAuth tokens, etc.) and
 * additional context such as client information, IP address, etc.
 * </p>
 *
 * <h3>Design Pattern:</h3>
 * <p>
 * Uses Builder Pattern for flexible construction of authentication requests.
 * </p>
 */
public class AuthenticationRequest {
    
    private final String authenticationMethod;
    private final Map<String, Object> credentials;
    private final Map<String, Object> context;
    
    private AuthenticationRequest(Builder builder) {
        this.authenticationMethod = builder.authenticationMethod;
        this.credentials = Map.copyOf(builder.credentials);
        this.context = Map.copyOf(builder.context);
    }
    
    /**
     * Gets the authentication method (e.g., "password", "oauth2", "mfa").
     *
     * @return the authentication method
     */
    public String getAuthenticationMethod() {
        return authenticationMethod;
    }
    
    /**
     * Gets the credentials map.
     *
     * @return the credentials map
     */
    public Map<String, Object> getCredentials() {
        return credentials;
    }
    
    /**
     * Gets a specific credential value.
     *
     * @param key the credential key
     * @return the credential value, or null if not found
     */
    public Object getCredential(String key) {
        return credentials.get(key);
    }
    
    /**
     * Gets the context map.
     *
     * @return the context map
     */
    public Map<String, Object> getContext() {
        return context;
    }
    
    /**
     * Gets a specific context value.
     *
     * @param key the context key
     * @return the context value, or null if not found
     */
    public Object getContextValue(String key) {
        return context.get(key);
    }
    
    /**
     * Creates a new builder for AuthenticationRequest.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for AuthenticationRequest.
     */
    public static class Builder {
        private String authenticationMethod;
        private final Map<String, Object> credentials = new java.util.HashMap<>();
        private final Map<String, Object> context = new java.util.HashMap<>();
        
        /**
         * Sets the authentication method.
         *
         * @param method the authentication method
         * @return this builder instance
         */
        public Builder authenticationMethod(String method) {
            this.authenticationMethod = method;
            return this;
        }
        
        /**
         * Adds a credential.
         *
         * @param key the credential key
         * @param value the credential value
         * @return this builder instance
         */
        public Builder credential(String key, Object value) {
            this.credentials.put(key, value);
            return this;
        }
        
        /**
         * Adds credentials from a map.
         *
         * @param credentials the credentials map
         * @return this builder instance
         */
        public Builder credentials(Map<String, Object> credentials) {
            if (credentials != null) {
                this.credentials.putAll(credentials);
            }
            return this;
        }
        
        /**
         * Adds context information.
         *
         * @param key the context key
         * @param value the context value
         * @return this builder instance
         */
        public Builder context(String key, Object value) {
            this.context.put(key, value);
            return this;
        }
        
        /**
         * Adds context from a map.
         *
         * @param context the context map
         * @return this builder instance
         */
        public Builder context(Map<String, Object> context) {
            if (context != null) {
                this.context.putAll(context);
            }
            return this;
        }
        
        /**
         * Builds the AuthenticationRequest.
         *
         * @return the built request
         * @throws IllegalStateException if authenticationMethod is not set
         */
        public AuthenticationRequest build() {
            if (authenticationMethod == null) {
                throw new IllegalStateException("Authentication method is required");
            }
            return new AuthenticationRequest(this);
        }
    }
}
