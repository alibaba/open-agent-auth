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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Pushed Authorization Request (PAR).
 * <p>
 * This class encapsulates a PAR request as defined in RFC 9126, containing
 * the authorization request JWT and related metadata.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ParRequest {
    
    @JsonProperty("requestJwt")
    private final String requestJwt;
    
    @JsonProperty("clientAssertion")
    private final String clientAssertion;
    
    @JsonProperty("clientAssertionType")
    private final String clientAssertionType;
    
    @JsonProperty("additionalParameters")
    private final Map<String, Object> additionalParameters;
    
    @JsonProperty("state")
    private final String state;
    
    @JsonCreator
    public ParRequest(
            @JsonProperty("requestJwt") String requestJwt,
            @JsonProperty("clientAssertion") String clientAssertion,
            @JsonProperty("clientAssertionType") String clientAssertionType,
            @JsonProperty("additionalParameters") Map<String, Object> additionalParameters,
            @JsonProperty("state") String state
    ) {
        this.requestJwt = requestJwt;
        this.clientAssertion = clientAssertion;
        this.clientAssertionType = clientAssertionType;
        this.additionalParameters = additionalParameters;
        this.state = state;
    }
    
    public String getRequestJwt() { return requestJwt; }
    public String getClientAssertion() { return clientAssertion; }
    public String getClientAssertionType() { return clientAssertionType; }
    public Map<String, Object> getAdditionalParameters() { return additionalParameters; }
    public String getState() { return state; }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String requestJwt;
        private String clientAssertion;
        private String clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        private Map<String, Object> additionalParameters;
        private String state;
        
        public Builder requestJwt(String requestJwt) {
            this.requestJwt = requestJwt;
            return this;
        }
        
        public Builder clientAssertion(String clientAssertion) {
            this.clientAssertion = clientAssertion;
            return this;
        }
        
        public Builder clientAssertionType(String clientAssertionType) {
            this.clientAssertionType = clientAssertionType;
            return this;
        }
        
        public Builder additionalParameters(Map<String, Object> additionalParameters) {
            this.additionalParameters = additionalParameters;
            return this;
        }
        
        public Builder state(String state) {
            this.state = state;
            return this;
        }
        
        public ParRequest build() {
            return new ParRequest(requestJwt, clientAssertion, clientAssertionType, additionalParameters, state);
        }
    }
}
