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
package com.alibaba.openagentauth.framework.model.validation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Result of request validation.
 * <p>
 * This class encapsulates the result of validating a request, including
 * the overall status, validation details for each layer, and any errors.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ValidationResult {
    
    @JsonProperty("valid")
    private final boolean valid;
    
    @JsonProperty("layerResults")
    private final List<LayerResult> layerResults;
    
    @JsonProperty("errors")
    private final List<String> errors;
    
    @JsonCreator
    public ValidationResult(
            @JsonProperty("valid") boolean valid,
            @JsonProperty("layerResults") List<LayerResult> layerResults,
            @JsonProperty("errors") List<String> errors
    ) {
        this.valid = valid;
        this.layerResults = layerResults;
        this.errors = errors;
    }
    
    public boolean isValid() { return valid; }
    public List<LayerResult> getLayerResults() { return layerResults; }
    public List<String> getErrors() { return errors; }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private boolean valid;
        private List<LayerResult> layerResults;
        private List<String> errors;
        
        public Builder valid(boolean valid) {
            this.valid = valid;
            return this;
        }
        
        public Builder layerResults(List<LayerResult> layerResults) {
            this.layerResults = layerResults;
            return this;
        }
        
        public Builder errors(List<String> errors) {
            this.errors = errors;
            return this;
        }
        
        public ValidationResult build() {
            return new ValidationResult(valid, layerResults, errors);
        }
    }
    
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class LayerResult {
        @JsonProperty("layer")
        private final int layer;
        
        @JsonProperty("layerName")
        private final String layerName;
        
        @JsonProperty("valid")
        private final boolean valid;
        
        @JsonProperty("message")
        private final String message;
        
        @JsonCreator
        public LayerResult(
                @JsonProperty("layer") int layer,
                @JsonProperty("layerName") String layerName,
                @JsonProperty("valid") boolean valid,
                @JsonProperty("message") String message
        ) {
            this.layer = layer;
            this.layerName = layerName;
            this.valid = valid;
            this.message = message;
        }
        
        public int getLayer() { return layer; }
        public String getLayerName() { return layerName; }
        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
        
        public static Builder builder() {
            return new Builder();
        }
        
        public static class Builder {
            private int layer;
            private String layerName;
            private boolean valid;
            private String message;
            
            public Builder layer(int layer) {
                this.layer = layer;
                return this;
            }
            
            public Builder layerName(String layerName) {
                this.layerName = layerName;
                return this;
            }
            
            public Builder valid(boolean valid) {
                this.valid = valid;
                return this;
            }
            
            public Builder message(String message) {
                this.message = message;
                return this;
            }
            
            public LayerResult build() {
                return new LayerResult(layer, layerName, valid, message);
            }
        }
    }
}
