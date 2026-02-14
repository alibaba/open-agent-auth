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

import java.util.Objects;

/**
 * Request for exchanging authorization code for ID Token.
 * <p>
 * This class encapsulates the parameters needed to exchange the authorization code
 * for an ID Token in the OIDC authorization code flow.
 * </p>
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ExchangeCodeForTokenRequest {
    
    /**
     * The authorization code received from the callback.
     * This field is REQUIRED.
     */
    private final String code;
    
    /**
     * The state value that was used in the authorization request.
     * This field is REQUIRED.
     */
    private final String state;
    
    /**
     * The redirect URI that was used in the authorization request.
     * This field is OPTIONAL.
     */
    private final String redirectUri;
    
    /**
     * The client ID for the OAuth 2.0 client.
     * This field is REQUIRED.
     */
    private final String clientId;
    
    private ExchangeCodeForTokenRequest(Builder builder) {
        this.code = builder.code;
        this.state = builder.state;
        this.redirectUri = builder.redirectUri;
        this.clientId = builder.clientId;
    }
    
    public String getCode() {
        return code;
    }
    
    public String getState() {
        return state;
    }
    
    public String getRedirectUri() {
        return redirectUri;
    }
    
    public String getClientId() {
        return clientId;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ExchangeCodeForTokenRequest that = (ExchangeCodeForTokenRequest) o;
        return Objects.equals(code, that.code) &&
               Objects.equals(state, that.state) &&
               Objects.equals(clientId, that.clientId);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(code, state, clientId);
    }
    
    @Override
    public String toString() {
        return "ExchangeCodeForTokenRequest{" +
                "code='" + code + '\'' +
                ", state='" + state + '\'' +
                ", clientId='" + clientId + '\'' +
                '}';
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String code;
        private String state;
        private String redirectUri;
        private String clientId;
        
        public Builder code(String code) {
            this.code = code;
            return this;
        }
        
        public Builder state(String state) {
            this.state = state;
            return this;
        }
        
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }
        
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }
        
        public ExchangeCodeForTokenRequest build() {
            if (ValidationUtils.isNullOrEmpty(code)) {
                throw new IllegalArgumentException("code is required");
            }
            if (ValidationUtils.isNullOrEmpty(state)) {
                throw new IllegalArgumentException("state is required");
            }
            if (ValidationUtils.isNullOrEmpty(clientId)) {
                throw new IllegalArgumentException("clientId is required");
            }
            return new ExchangeCodeForTokenRequest(this);
        }
    }
}