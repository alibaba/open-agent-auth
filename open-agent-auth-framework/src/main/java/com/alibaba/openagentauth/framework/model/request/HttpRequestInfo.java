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
 * Information about an HTTP request for WPT generation.
 * <p>
 * This class encapsulates the HTTP request information needed to generate
 * a Workload Proof Token (WPT) according to RFC 9421.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HttpRequestInfo {
    
    @JsonProperty("method")
    private final String method;
    
    @JsonProperty("uri")
    private final String uri;
    
    @JsonProperty("headers")
    private final Map<String, String> headers;
    
    @JsonProperty("body")
    private final String body;
    
    @JsonCreator
    public HttpRequestInfo(
            @JsonProperty("method") String method,
            @JsonProperty("uri") String uri,
            @JsonProperty("headers") Map<String, String> headers,
            @JsonProperty("body") String body
    ) {
        this.method = method;
        this.uri = uri;
        this.headers = headers;
        this.body = body;
    }
    
    public String getMethod() { return method; }
    public String getUri() { return uri; }
    public Map<String, String> getHeaders() { return headers; }
    public String getBody() { return body; }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static class Builder {
        private String method;
        private String uri;
        private Map<String, String> headers;
        private String body;
        
        public Builder method(String method) {
            this.method = method;
            return this;
        }
        
        public Builder uri(String uri) {
            this.uri = uri;
            return this;
        }
        
        public Builder headers(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }
        
        public Builder body(String body) {
            this.body = body;
            return this;
        }
        
        public HttpRequestInfo build() {
            return new HttpRequestInfo(method, uri, headers, body);
        }
    }
}
