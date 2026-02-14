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

import com.alibaba.openagentauth.framework.model.workload.WorkloadContext;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response containing authorization URL and related information.
 * <p>
 * This response provides the complete authorization redirect URL and
 * contextual information needed for the OAuth flow continuation.
 * </p>
 *
 * @since 1.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RequestAuthUrlResponse {
    
    /**
     * The complete authorization redirect URL.
     * <p>
     * This URL includes the authorization endpoint, request_uri, and state parameters.
     * The frontend should redirect the user to this URL to initiate the authorization flow.
     * </p>
     */
    @JsonProperty("authorizationUrl")
    private final String authorizationUrl;
    
    /**
     * The PAR request URI used in the authorization URL.
     * <p>
     * This is the request_uri returned by the PAR endpoint, which contains
     * the pushed authorization request details.
     * </p>
     */
    @JsonProperty("requestUri")
    private final String requestUri;
    
    /**
     * The state parameter used in the authorization flow.
     * <p>
     * This parameter should be validated in the callback to prevent CSRF attacks
     * and restore session context.
     * </p>
     */
    @JsonProperty("state")
    private final String state;
    
    /**
     * The workload context for later use in callback.
     * <p>
     * This context contains the WIT, key pair, and workload information needed
     * for token exchange and context preparation.
     * </p>
     */
    @JsonProperty("workloadContext")
    private final WorkloadContext workloadContext;
    
    /**
     * The redirect URI used in the PAR request.
     * <p>
     * This is the callback URL where the authorization code will be sent.
     * It must match the redirect URI registered with the OAuth client.
     * </p>
     */
    @JsonProperty("redirectUri")
    private final String redirectUri;
    
    private RequestAuthUrlResponse(Builder builder) {
        this.authorizationUrl = builder.authorizationUrl;
        this.requestUri = builder.requestUri;
        this.state = builder.state;
        this.workloadContext = builder.workloadContext;
        this.redirectUri = builder.redirectUri;
    }
    
    public String getAuthorizationUrl() {
        return authorizationUrl;
    }
    
    public String getRequestUri() {
        return requestUri;
    }
    
    public String getState() {
        return state;
    }
    
    public WorkloadContext getWorkloadContext() {
        return workloadContext;
    }
    
    public String getRedirectUri() {
        return redirectUri;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for RequestAuthUrlResponse.
     */
    public static class Builder {
        private String authorizationUrl;
        private String requestUri;
        private String state;
        private WorkloadContext workloadContext;
        private String redirectUri;
        
        public Builder authorizationUrl(String authorizationUrl) {
            this.authorizationUrl = authorizationUrl;
            return this;
        }
        
        public Builder requestUri(String requestUri) {
            this.requestUri = requestUri;
            return this;
        }
        
        public Builder state(String state) {
            this.state = state;
            return this;
        }
        
        public Builder workloadContext(WorkloadContext workloadContext) {
            this.workloadContext = workloadContext;
            return this;
        }
        
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }
        
        public RequestAuthUrlResponse build() {
            return new RequestAuthUrlResponse(this);
        }
    }
}
