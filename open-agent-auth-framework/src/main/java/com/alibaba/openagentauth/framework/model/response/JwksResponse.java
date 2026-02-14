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

import java.util.List;
import java.util.Map;

/**
 * JWKS (JSON Web Key Set) response.
 * <p>
 * This class represents a JWKS document containing public keys used for
 * token signature verification.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7517.html">RFC 7517 - JSON Web Key (JWK)</a>
 */
public class JwksResponse {
    
    private final List<Jwk> keys;
    private final Map<String, Object> additionalMetadata;
    
    private JwksResponse(Builder builder) {
        this.keys = List.copyOf(builder.keys);
        this.additionalMetadata = Map.copyOf(builder.additionalMetadata);
    }
    
    /**
     * Gets the list of JWKs.
     *
     * @return the list of keys
     */
    public List<Jwk> getKeys() {
        return keys;
    }
    
    /**
     * Gets additional metadata.
     *
     * @return the metadata map
     */
    public Map<String, Object> getAdditionalMetadata() {
        return additionalMetadata;
    }
    
    /**
     * Creates a new builder for JwksResponse.
     */
    public static Builder builder() {
        return new Builder();
    }
    
    /**
     * Builder for JwksResponse.
     */
    public static class Builder {
        private final List<Jwk> keys = new java.util.ArrayList<>();
        private final Map<String, Object> additionalMetadata = new java.util.HashMap<>();
        
        public Builder addKey(Jwk key) {
            this.keys.add(key);
            return this;
        }
        
        public Builder addMetadata(String key, Object value) {
            this.additionalMetadata.put(key, value);
            return this;
        }
        
        public JwksResponse build() {
            return new JwksResponse(this);
        }
    }
    
    /**
     * JSON Web Key representation.
     */
    public static class Jwk {
        private final String kty;
        private final String use;
        private final String keyId;
        private final String algorithm;
        private final Map<String, Object> parameters;
        
        private Jwk(Builder builder) {
            this.kty = builder.kty;
            this.use = builder.use;
            this.keyId = builder.keyId;
            this.algorithm = builder.algorithm;
            this.parameters = Map.copyOf(builder.parameters);
        }
        
        public String getKty() { return kty; }
        public String getUse() { return use; }
        public String getKeyId() { return keyId; }
        public String getAlgorithm() { return algorithm; }
        public Map<String, Object> getParameters() { return parameters; }
        
        public static Builder builder() {
            return new Builder();
        }
        
        public static class Builder {
            private String kty;
            private String use;
            private String keyId;
            private String algorithm;
            private final Map<String, Object> parameters = new java.util.HashMap<>();
            
            public Builder kty(String kty) { this.kty = kty; return this; }
            public Builder use(String use) { this.use = use; return this; }
            public Builder keyId(String keyId) { this.keyId = keyId; return this; }
            public Builder algorithm(String algorithm) { this.algorithm = algorithm; return this; }
            public Builder parameter(String key, Object value) { this.parameters.put(key, value); return this; }
            
            public Jwk build() {
                return new Jwk(this);
            }
        }
    }
}
