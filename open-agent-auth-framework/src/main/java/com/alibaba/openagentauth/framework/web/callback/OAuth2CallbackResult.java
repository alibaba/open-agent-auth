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

import java.util.Map;

/**
 * OAuth2 callback processing result.
 * <p>
 * Encapsulates callback processing results, supporting success redirects and error responses.
 * </p>
 *
 * @since 1.0
 */
public class OAuth2CallbackResult {
    
    private final boolean success;
    private final String redirectUrl;
    private final Map<String, String> errorResponse;
    private final int statusCode;
    
    private OAuth2CallbackResult(boolean success, String redirectUrl, 
                          Map<String, String> errorResponse, int statusCode) {
        this.success = success;
        this.redirectUrl = redirectUrl;
        this.errorResponse = errorResponse;
        this.statusCode = statusCode;
    }
    
    /**
     * Create successful redirect result.
     *
     * @param url redirect URL
     * @return callback result
     */
    public static OAuth2CallbackResult redirect(String url) {
        return new OAuth2CallbackResult(true, url, null, 302);
    }
    
    /**
     * Create error response result.
     *
     * @param statusCode HTTP status code
     * @param errorResponse error response
     * @return callback result
     */
    public static OAuth2CallbackResult error(int statusCode, Map<String, String> errorResponse) {
        return new OAuth2CallbackResult(false, null, errorResponse, statusCode);
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public String getRedirectUrl() {
        return redirectUrl;
    }
    
    public Map<String, String> getErrorResponse() {
        return errorResponse;
    }
    
    public int getStatusCode() {
        return statusCode;
    }
}
