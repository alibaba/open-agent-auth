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
package com.alibaba.openagentauth.core.util;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * A builder for constructing URL query strings.
 * <p>
 * This class provides a fluent API for building URL query strings without
 * manual string concatenation. It handles parameter encoding and separator
 * management automatically.
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * String query = new UriQueryBuilder()
 *     .add("client_id", "my-client")
 *     .add("response_type", "code")
 *     .add("redirect_uri", "https://example.com/callback")
 *     .build();
 * }</pre>
 * <p>
 * For URL-encoded values, use {@link #addEncoded(String, String)}:
 * </p>
 * <pre>{@code
 * String query = new UriQueryBuilder()
 *     .addEncoded("client_id", "my-client")
 *     .addEncoded("redirect_uri", "https://example.com/callback")
 *     .build();
 * }</pre>
 * <p>
 * For existing query strings, use {@link #appendRaw(String)}:
 * </p>
 * <pre>{@code
 * String query = new UriQueryBuilder()
 *     .appendRaw("existing=param")
 *     .add("new_param", "value")
 *     .build();
 * }</pre>
 *
 * @since 1.0
 */
public class UriQueryBuilder {

    private final StringBuilder builder = new StringBuilder();
    private boolean hasParams = false;

    /**
     * Creates a new empty query builder.
     */
    public UriQueryBuilder() {
    }

    /**
     * Appends a raw query string (for existing parameters).
     * <p>
     * This method is useful when you need to prepend existing query parameters
     * to a new query string. The raw query is appended as-is without modification.
     * </p>
     *
     * @param rawQuery the raw query string to append (may be null or empty)
     * @return this builder for method chaining
     */
    public UriQueryBuilder appendRaw(String rawQuery) {
        if (!ValidationUtils.isNullOrEmpty(rawQuery)) {
            builder.append(rawQuery);
            hasParams = true;
        }
        return this;
    }

    /**
     * Adds a query parameter with the given name and value.
     * <p>
     * The value should be URL-encoded before being passed to this method.
     * The builder will automatically add the appropriate separator (&) if
     * there are already parameters.
     * </p>
     *
     * @param name the parameter name (must not be null)
     * @param value the parameter value (must not be null, should be URL-encoded)
     * @return this builder for method chaining
     * @throws IllegalArgumentException if name or value is null
     */
    public UriQueryBuilder add(String name, String value) {
        ValidationUtils.validateNotNull(name, "Parameter name");
        ValidationUtils.validateNotNull(value, "Parameter value");
        
        if (hasParams) {
            builder.append("&");
        }
        builder.append(name).append("=").append(value);
        hasParams = true;
        return this;
    }

    /**
     * Adds a query parameter with the given name and value, automatically URL-encoding both.
     * <p>
     * This method automatically URL-encodes both the parameter name and value using UTF-8 encoding.
     * Use this method when you want the builder to handle URL encoding for you.
     * </p>
     *
     * @param name the parameter name (must not be null)
     * @param value the parameter value (must not be null)
     * @return this builder for method chaining
     * @throws IllegalArgumentException if name or value is null
     */
    public UriQueryBuilder addEncoded(String name, String value) {
        ValidationUtils.validateNotNull(name, "Parameter name");
        ValidationUtils.validateNotNull(value, "Parameter value");
        
        if (hasParams) {
            builder.append("&");
        }
        builder.append(URLEncoder.encode(name, StandardCharsets.UTF_8))
              .append("=")
              .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        hasParams = true;
        return this;
    }

    /**
     * Builds the final query string.
     *
     * @return the constructed query string, or empty string if no parameters were added
     */
    public String build() {
        return builder.toString();
    }

}
