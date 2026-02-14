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
package com.alibaba.openagentauth.sample.agent.adapter.api;

/**
 * API server configuration.
 * <p>
 * Represents the configuration for an API server that can be integrated
 * with the agent for tool access via REST APIs.
 * </p>
 */
public class ApiServerConfig {

    private String name;
    private String baseUrl;
    private String description;
    private String authToken;

    /**
     * Gets the name of the API server.
     *
     * @return the server name
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the name of the API server.
     *
     * @param name the server name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Gets the base URL of the API server.
     *
     * @return the base URL
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * Sets the base URL of the API server.
     *
     * @param baseUrl the base URL
     */
    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /**
     * Gets the description of the API server.
     *
     * @return the server description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Sets the description of the API server.
     *
     * @param description the server description
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Gets the authentication token for the API server.
     *
     * @return the auth token
     */
    public String getAuthToken() {
        return authToken;
    }

    /**
     * Sets the authentication token for the API server.
     *
     * @param authToken the auth token
     */
    public void setAuthToken(String authToken) {
        this.authToken = authToken;
    }
}
