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

import java.net.http.HttpResponse;

/**
 * Default implementation of {@link OpaHttpResponse} wrapping Java's {@link HttpResponse}.
 * <p>
 * This implementation delegates to the standard Java 11+ HttpResponse for
 * actual HTTP responses from OPA servers. It provides the production
 * implementation of the OPA HTTP response interface.
 * </p>
 *
 * @param <T> the response body type
 * @see OpaHttpResponse
 * @see OpaHttpClient
 * @since 1.0
 */
public class DefaultOpaHttpResponse<T> implements OpaHttpResponse<T> {

    private final HttpResponse<T> response;

    /**
     * Creates a new DefaultOpaHttpResponse wrapping the given HttpResponse.
     *
     * @param response the HTTP response to wrap
     */
    public DefaultOpaHttpResponse(HttpResponse<T> response) {
        this.response = response;
    }

    @Override
    public int statusCode() {
        return response.statusCode();
    }

    @Override
    public T body() {
        return response.body();
    }

}
