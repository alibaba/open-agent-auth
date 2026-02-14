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

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * HTTP client interface for OPA communication.
 * <p>
 * This interface wraps Java's {@link java.net.http.HttpClient} to provide
 * better testability by allowing mock implementations. It abstracts the
 * HTTP communication details needed for OPA policy evaluation.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Adapter Pattern</p>
 * <p>
 * This interface enables dependency injection of HTTP clients, making it
 * easier to test {@link OpaRestPolicyEvaluator} without requiring a real
 * OPA server or dealing with Java version compatibility issues when mocking
 * core classes.
 * </p>
 *
 * @see OpaRestPolicyEvaluator
 * @since 1.0
 */
public interface OpaHttpClient {

    /**
     * Sends an HTTP request and returns the response.
     * <p>
     * This method wraps {@link java.net.http.HttpClient#send(HttpRequest, HttpResponse.BodyHandler)}
     * to provide a testable interface.
     * </p>
     *
     * @param request the HTTP request to send
     * @param responseHandler the response body handler
     * @param <T> the response body type
     * @return the HTTP response
     * @throws Exception if an I/O error occurs or the request is interrupted
     */
    <T> OpaHttpResponse<T> send(HttpRequest request, OpaBodyHandler<T> responseHandler) throws Exception;
}