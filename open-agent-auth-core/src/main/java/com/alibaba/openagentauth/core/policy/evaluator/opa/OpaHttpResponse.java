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

/**
 * HTTP response interface for OPA communication.
 * <p>
 * This interface wraps Java's {@link java.net.http.HttpResponse} to provide
 * better testability by allowing mock implementations. It abstracts the
 * HTTP response details needed for OPA policy evaluation.
 * </p>
 *
 * @see OpaHttpClient
 * @since 1.0
 */
public interface OpaHttpResponse<T> {

    /**
     * Gets the HTTP status code.
     *
     * @return the status code
     */
    int statusCode();

    /**
     * Gets the response body.
     *
     * @return the response body
     */
    T body();

}
