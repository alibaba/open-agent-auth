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
 * Request for initiating OIDC authorization flow.
 * <p>
 * This class encapsulates the parameters needed to initiate the OIDC authorization code flow.
 * </p>
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class InitiateAuthorizationRequest {
    
    /**
     * The callback URL where the authorization code will be sent.
     * This field is REQUIRED.
     */
    private final String redirectUri;
    
    /**
     * A random value to prevent CSRF attacks.
     * This field is REQUIRED.
     */
    private final String state;
    
    private InitiateAuthorizationRequest(Builder builder) {
        this.redirectUri = builder.redirectUri;
        this.state = builder.state;
    }
    
    public String getRedirectUri() {
        return redirectUri;
    }
    
    public String getState() {
        return state;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InitiateAuthorizationRequest that = (InitiateAuthorizationRequest) o;
        return Objects.equals(redirectUri, that.redirectUri) &&
               Objects.equals(state, that.state);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(redirectUri, state);
    }
    
    @Override
    public String toString() {
        return "InitiateAuthorizationRequest{" +
                "redirectUri='" + redirectUri + '\'' +
                ", state='" + state + '\'' +
                '}';
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String redirectUri;
        private String state;
        
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }
        
        public Builder state(String state) {
            this.state = state;
            return this;
        }
        
        public InitiateAuthorizationRequest build() {
            if (ValidationUtils.isNullOrEmpty(redirectUri)) {
                throw new IllegalArgumentException("redirectUri is required");
            }
            if (ValidationUtils.isNullOrEmpty(state)) {
                throw new IllegalArgumentException("state is required");
            }
            return new InitiateAuthorizationRequest(this);
        }
    }
}