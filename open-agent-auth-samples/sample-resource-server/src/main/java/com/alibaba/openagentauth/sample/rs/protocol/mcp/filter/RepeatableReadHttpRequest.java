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
package com.alibaba.openagentauth.sample.rs.protocol.mcp.filter;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * A wrapper for {@link HttpServletRequest} that allows multiple reads of the request body.
 * <p>
 * This class caches the request body content in memory, enabling multiple
 * reads without consuming the underlying input stream. This is essential
 * for filters that need to read the request body for inspection while
 * allowing downstream components to also read the body.
 * </p>
 * <p>
 * <b>Usage Example:</b>
 * <pre>{@code
 * @Override
 * protected void doFilterInternal(HttpServletRequest request, 
 *                                HttpServletResponse response, 
 *                                FilterChain filterChain) 
 *         throws ServletException, IOException {
 *     RepeatableReadHttpRequest wrappedRequest = new RepeatableReadHttpRequest(request);
 *     
 *     // Read body for inspection
 *     String body = wrappedRequest.getBody();
 *     
 *     // Pass to filter chain - downstream can also read the body
 *     filterChain.doFilter(wrappedRequest, response);
 * }
 * }</pre>
 * </p>
 *
 * @since 1.0
 */
public class RepeatableReadHttpRequest extends HttpServletRequestWrapper {
    
    private final byte[] cachedBody;
    
    /**
     * Creates a new wrapper that caches the request body.
     *
     * @param request the original HTTP request
     * @throws IOException if reading the request body fails
     */
    public RepeatableReadHttpRequest(HttpServletRequest request) throws IOException {
        super(request);
        this.cachedBody = readRequestBody(request);
    }
    
    /**
     * Reads the entire request body from the original request.
     *
     * @param request the HTTP request
     * @return the request body as a byte array
     * @throws IOException if reading fails
     */
    private byte[] readRequestBody(HttpServletRequest request) throws IOException {
        return request.getInputStream().readAllBytes();
    }
    
    /**
     * Gets the cached request body as a string.
     *
     * @return the request body as a UTF-8 string
     */
    public String getBody() {
        return new String(cachedBody, StandardCharsets.UTF_8);
    }
    
    /**
     * Gets the cached request body as a byte array.
     *
     * @return the request body as a byte array
     */
    public byte[] getCachedBody() {
        return cachedBody;
    }
    
    @Override
    public ServletInputStream getInputStream() {
        return new CachedBodyServletInputStream(cachedBody);
    }
    
    @Override
    public BufferedReader getReader() {
        return new BufferedReader(
            new InputStreamReader(
                new ByteArrayInputStream(cachedBody),
                StandardCharsets.UTF_8
            )
        );
    }
    
    /**
     * A {@link ServletInputStream} implementation that reads from a cached byte array.
     */
    private static class CachedBodyServletInputStream extends ServletInputStream {
        
        private final ByteArrayInputStream inputStream;
        
        /**
         * Creates a new input stream from the cached body.
         *
         * @param cachedBody the cached request body
         */
        public CachedBodyServletInputStream(byte[] cachedBody) {
            this.inputStream = new ByteArrayInputStream(cachedBody);
        }
        
        @Override
        public boolean isFinished() {
            return inputStream.available() == 0;
        }
        
        @Override
        public boolean isReady() {
            return true;
        }
        
        @Override
        public void setReadListener(ReadListener readListener) {
            throw new UnsupportedOperationException("setReadListener is not supported");
        }
        
        @Override
        public int read() {
            return inputStream.read();
        }
    }
}
