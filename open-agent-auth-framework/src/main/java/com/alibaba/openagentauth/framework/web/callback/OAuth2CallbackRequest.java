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
package com.alibaba.openagentauth.framework.web.callback;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import jakarta.servlet.http.HttpServletRequest;

/**
 * OAuth2 callback request.
 * <p>
 * Encapsulates all OAuth2 callback parameters with type-safe access.
 * </p>
 *
 * @since 1.0
 */
public class OAuth2CallbackRequest {
    
    private final String code;
    private final String state;
    private final String error;
    private final String errorDescription;
    private final HttpServletRequest httpRequest;
    
    public OAuth2CallbackRequest(String code, String state, String error, 
                          String errorDescription, HttpServletRequest httpRequest) {
        this.code = code;
        this.state = state;
        this.error = error;
        this.errorDescription = errorDescription;
        this.httpRequest = httpRequest;
    }
    
    public String getCode() {
        return code;
    }
    
    public String getState() {
        return state;
    }
    
    public String getError() {
        return error;
    }
    
    public String getErrorDescription() {
        return errorDescription;
    }
    
    public HttpServletRequest getHttpRequest() {
        return httpRequest;
    }
    
    /**
     * Check if contains error.
     *
     * @return true if contains error
     */
    public boolean hasError() {
        return !ValidationUtils.isNullOrEmpty(error);
    }
    
    /**
     * Build OAuth2CallbackRequest from HttpServletRequest.
     *
     * @param request HTTP request
     * @return callback request
     */
    public static OAuth2CallbackRequest from(HttpServletRequest request) {
        return new OAuth2CallbackRequest(
            request.getParameter("code"),
            request.getParameter("state"),
            request.getParameter("error"),
            request.getParameter("error_description"),
            request
        );
    }
}