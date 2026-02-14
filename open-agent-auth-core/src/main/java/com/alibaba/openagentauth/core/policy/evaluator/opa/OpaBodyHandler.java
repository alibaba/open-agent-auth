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
 * Body handler interface for OPA HTTP responses.
 * <p>
 * This interface wraps Java's {@link HttpResponse.BodyHandler} to provide
 * better testability by allowing mock implementations.
 * </p>
 *
 * @param <T> the response body type
 * @since 1.0
 */
public interface OpaBodyHandler<T> {

    /**
     * Converts the Java HttpResponse.BodyHandler to OpaBodyHandler.
     *
     * @param bodyHandler the Java HttpResponse.BodyHandler
     * @param <T> the response body type
     * @return the OpaBodyHandler
     */
    static <T> OpaBodyHandler<T> of(HttpResponse.BodyHandler<T> bodyHandler) {
        return () -> bodyHandler;
    }

    /**
     * Gets the underlying Java HttpResponse.BodyHandler.
     *
     * @return the Java HttpResponse.BodyHandler
     */
    HttpResponse.BodyHandler<T> toJavaBodyHandler();

}
