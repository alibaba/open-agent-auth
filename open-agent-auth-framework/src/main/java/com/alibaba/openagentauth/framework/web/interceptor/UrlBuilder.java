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
package com.alibaba.openagentauth.framework.web.interceptor;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Utility class for building URLs from HTTP requests.
 * <p>
 * This class provides helper methods for constructing URLs based on the
 * current request's scheme, server name, port, and context path.
 * </p>
 *
 * @since 1.0
 */
public final class UrlBuilder {

    private UrlBuilder() {
        // Utility class - prevent instantiation
    }

    /**
     * Builds a base URL from the request.
     * <p>
     * The base URL includes scheme, server name, port (if non-default), and context path.
     * </p>
     *
     * @param request the HTTP request
     * @return the base URL (e.g., "https://example.com:8080/context")
     */
    public static String buildBaseUrl(HttpServletRequest request) {
        StringBuilder url = new StringBuilder();
        
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = request.getServerPort();
        String contextPath = request.getContextPath();
        
        url.append(scheme).append("://").append(serverName);
        
        // Add port if not default
        if ((scheme.equals("http") && serverPort != 80) ||
            (scheme.equals("https") && serverPort != 443)) {
            url.append(":").append(serverPort);
        }
        
        url.append(contextPath);
        
        return url.toString();
    }

    /**
     * Builds a full URL from the request with a specific path.
     * <p>
     * This method combines the base URL with the specified path.
     * </p>
     *
     * @param request the HTTP request
     * @param path the path to append (e.g., "/callback", "/login")
     * @return the full URL
     */
    public static String buildUrl(HttpServletRequest request, String path) {
        return buildBaseUrl(request) + path;
    }

    /**
     * Builds the current request URL.
     * <p>
     * This method reconstructs the full URL of the current request,
     * including query string if present.
     * </p>
     *
     * @param request the HTTP request
     * @return the current request URL
     */
    public static String buildCurrentRequestUrl(HttpServletRequest request) {
        StringBuilder url = new StringBuilder();
        url.append(buildBaseUrl(request));
        url.append(request.getRequestURI());
        
        String queryString = request.getQueryString();
        if (queryString != null && !queryString.isEmpty()) {
            url.append("?").append(queryString);
        }
        
        return url.toString();
    }

    /**
     * Builds a URL with query parameters.
     * <p>
     * This method appends query parameters to a base URL.
     * </p>
     *
     * @param baseUrl the base URL
     * @param params the query parameters (key-value pairs)
     * @return the URL with query parameters
     */
    public static String buildUrlWithParams(String baseUrl, String... params) {
        if (params.length % 2 != 0) {
            throw new IllegalArgumentException("Params must be in key-value pairs");
        }
        
        StringBuilder url = new StringBuilder(baseUrl);
        url.append("?");
        
        for (int i = 0; i < params.length; i += 2) {
            if (i > 0) {
                url.append("&");
            }
            url.append(params[i]).append("=").append(java.net.URLEncoder.encode(params[i + 1], java.nio.charset.StandardCharsets.UTF_8));
        }
        
        return url.toString();
    }
}
