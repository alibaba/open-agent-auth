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
package com.alibaba.openagentauth.core.policy.evaluator.opa;

import com.alibaba.openagentauth.core.policy.evaluator.OpaRestPolicyEvaluator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Default implementation of {@link OpaHttpClient} using Java's {@link HttpClient}.
 * <p>
 * This implementation delegates to the standard Java 11+ HttpClient for
 * actual HTTP communication with OPA servers. It provides the production
 * implementation of the OPA HTTP client interface.
 * </p>
 *
 * @see OpaHttpClient
 * @see OpaRestPolicyEvaluator
 * @since 1.0
 */
public class DefaultOpaHttpClient implements OpaHttpClient {

    private static final Logger logger = LoggerFactory.getLogger(DefaultOpaHttpClient.class);

    private final HttpClient httpClient;

    /**
     * Creates a new DefaultOpaHttpClient with default settings.
     */
    public DefaultOpaHttpClient() {
        this.httpClient = HttpClient.newHttpClient();
        logger.debug("DefaultOpaHttpClient initialized with default HttpClient");
    }

    /**
     * Creates a new DefaultOpaHttpClient with custom timeout.
     *
     * @param timeout the connection timeout
     */
    public DefaultOpaHttpClient(Duration timeout) {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
        logger.debug("DefaultOpaHttpClient initialized with timeout: {}", timeout);
    }

    /**
     * Creates a new DefaultOpaHttpClient with a custom HttpClient.
     * <p>
     * This constructor allows for advanced customization of the underlying
     * HttpClient, such as custom executors, SSL contexts, or proxies.
     * </p>
     *
     * @param httpClient the custom HttpClient to use
     */
    public DefaultOpaHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
        logger.debug("DefaultOpaHttpClient initialized with custom HttpClient");
    }

    @Override
    public <T> OpaHttpResponse<T> send(HttpRequest request, OpaBodyHandler<T> responseHandler) throws Exception {
        logger.debug("Sending HTTP request to: {}", request.uri());
        HttpResponse<T> response = httpClient.send(request, responseHandler.toJavaBodyHandler());
        logger.debug("Received HTTP response with status: {}", response.statusCode());
        return new DefaultOpaHttpResponse<>(response);
    }
}