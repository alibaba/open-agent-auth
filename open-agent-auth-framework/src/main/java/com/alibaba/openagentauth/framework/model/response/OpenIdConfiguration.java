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
 * OIDC discovery configuration.
 * <p>
 * This class represents the standard OIDC discovery document containing
 * endpoints and metadata for an Identity Provider.
 * </p>
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>
 */
public class OpenIdConfiguration {
    
    private final String issuer;
    private final String authorizationEndpoint;
    private final String tokenEndpoint;
    private final String userInfoEndpoint;
    private final String jwksUri;
    private final String responseTypesSupported;
    private final String subjectTypesSupported;
    private final String idTokenSigningAlgValuesSupported;
    private final Map<String, Object> additionalMetadata;
    
    private OpenIdConfiguration(Builder builder) {
        this.issuer = builder.issuer;
        this.authorizationEndpoint = builder.authorizationEndpoint;
        this.tokenEndpoint = builder.tokenEndpoint;
        this.userInfoEndpoint = builder.userInfoEndpoint;
        this.jwksUri = builder.jwksUri;
        this.responseTypesSupported = builder.responseTypesSupported;
        this.subjectTypesSupported = builder.subjectTypesSupported;
        this.idTokenSigningAlgValuesSupported = builder.idTokenSigningAlgValuesSupported;
        this.additionalMetadata = Map.copyOf(builder.additionalMetadata);
    }
    
    // Getters
    public String getIssuer() { return issuer; }
    public String getAuthorizationEndpoint() { return authorizationEndpoint; }
    public String getTokenEndpoint() { return tokenEndpoint; }
    public String getUserInfoEndpoint() { return userInfoEndpoint; }
    public String getJwksUri() { return jwksUri; }
    public String getResponseTypesSupported() { return responseTypesSupported; }
    public String getSubjectTypesSupported() { return subjectTypesSupported; }
    public String getIdTokenSigningAlgValuesSupported() { return idTokenSigningAlgValuesSupported; }
    public Map<String, Object> getAdditionalMetadata() { return additionalMetadata; }
    
    /**
     * Creates a new builder for OpenIdConfiguration.
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for OpenIdConfiguration.
     */
    public static class Builder {
        private String issuer;
        private String authorizationEndpoint;
        private String tokenEndpoint;
        private String userInfoEndpoint;
        private String jwksUri;
        private String responseTypesSupported = "code";
        private String subjectTypesSupported = "public";
        private String idTokenSigningAlgValuesSupported = "RS256";
        private final Map<String, Object> additionalMetadata = new java.util.HashMap<>();
        
        public Builder issuer(String issuer) { this.issuer = issuer; return this; }
        public Builder authorizationEndpoint(String endpoint) { this.authorizationEndpoint = endpoint; return this; }
        public Builder tokenEndpoint(String endpoint) { this.tokenEndpoint = endpoint; return this; }
        public Builder userInfoEndpoint(String endpoint) { this.userInfoEndpoint = endpoint; return this; }
        public Builder jwksUri(String jwksUri) { this.jwksUri = jwksUri; return this; }
        public Builder responseTypesSupported(String types) { this.responseTypesSupported = types; return this; }
        public Builder subjectTypesSupported(String types) { this.subjectTypesSupported = types; return this; }
        public Builder idTokenSigningAlgValuesSupported(String algs) { this.idTokenSigningAlgValuesSupported = algs; return this; }
        public Builder addMetadata(String key, Object value) { this.additionalMetadata.put(key, value); return this; }
        
        public OpenIdConfiguration build() {
            return new OpenIdConfiguration(this);
        }
    }
}
