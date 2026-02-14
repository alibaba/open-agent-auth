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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Request for initiating OIDC authentication.
 * <p>
 * This class encapsulates the parameters required to initiate an OpenID Connect
 * authentication flow according to OpenID Connect Core 1.0 specification.
 * </p>
 * 
 * <h3>Standard Parameters:</h3>
 * <ul>
 *   <li><b>clientId:</b> REQUIRED - The client identifier</li>
 *   <li><b>redirectUri:</b> REQUIRED - The redirect URI where the callback will be sent</li>
 *   <li><b>scope:</b> REQUIRED - The requested scope (e.g., "openid profile email")</li>
 *   <li><b>state:</b> OPTIONAL - The state parameter for CSRF protection (auto-generated if not provided)</li>
 *   <li><b>nonce:</b> OPTIONAL - The nonce parameter for replay protection (auto-generated if not provided)</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#Authentication">OpenID Connect Core 1.0 - Authentication</a>
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class InitiateAuthenticationRequest {
    
    private final String clientId;
    private final String redirectUri;
    private final String scope;
    private String state;
    private String nonce;
    
    /**
     * Creates a new InitiateAuthenticationRequest with required parameters.
     *
     * @param clientId the client identifier
     * @param redirectUri the redirect URI
     * @param scope the requested scope
     */
    public InitiateAuthenticationRequest(String clientId, String redirectUri, String scope) {
        this.clientId = ValidationUtils.validateNotNull(clientId, "Client ID");
        this.redirectUri = ValidationUtils.validateNotNull(redirectUri, "Redirect URI");
        this.scope = ValidationUtils.validateNotNull(scope, "Scope");
    }
    
    /**
     * Creates a new InitiateAuthenticationRequest with all parameters.
     *
     * @param clientId the client identifier
     * @param redirectUri the redirect URI
     * @param scope the requested scope
     * @param state the state parameter
     * @param nonce the nonce parameter
     */
    public InitiateAuthenticationRequest(String clientId, String redirectUri, String scope, 
                                         String state, String nonce) {
        this(clientId, redirectUri, scope);
        this.state = state;
        this.nonce = nonce;
    }
    
    public String getClientId() {
        return clientId;
    }
    
    public String getRedirectUri() {
        return redirectUri;
    }
    
    public String getScope() {
        return scope;
    }
    
    public String getState() {
        return state;
    }
    
    public void setState(String state) {
        this.state = state;
    }
    
    public String getNonce() {
        return nonce;
    }
    
    public void setNonce(String nonce) {
        this.nonce = nonce;
    }
    
    /**
     * Creates a builder for InitiateAuthenticationRequest.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for InitiateAuthenticationRequest.
     */
    public static class Builder {
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private String nonce;
        
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }
        
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }
        
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }
        
        public Builder state(String state) {
            this.state = state;
            return this;
        }
        
        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }
        
        public InitiateAuthenticationRequest build() {
            return new InitiateAuthenticationRequest(clientId, redirectUri, scope, state, nonce);
        }
    }
}