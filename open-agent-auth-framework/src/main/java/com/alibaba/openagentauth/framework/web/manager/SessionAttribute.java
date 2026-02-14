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
package com.alibaba.openagentauth.framework.web.manager;

import java.util.Objects;

/**
 * Type-safe session attribute definition using TypeToken pattern.
 * <p>
 * This class provides compile-time type safety for session attributes
 * by capturing the generic type information at runtime. It solves the
 * type erasure problem of Java generics.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Type Token Pattern (Effective Java Item 29)
 * </p>
 * <p>
 * <b>Usage:</b></p>
 * <pre>
 * // Define session attributes as constants
 * public static final SessionAttribute&lt;String&gt; AUTHENTICATED_USER =
 *     new SessionAttribute&lt;&gt;("authenticated_user", String.class);
 * 
 * public static final SessionAttribute&lt;List&lt;ChatMessage&gt;&gt; CONVERSATION_HISTORY =
 *     new SessionAttribute&lt;&gt;("conversation_history", List.class);
 * 
 * // Use in SessionManager
 * String userId = sessionManager.getAttribute(session, AUTHENTICATED_USER);
 * sessionManager.setAttribute(session, AUTHENTICATED_USER, "user123");
 * </pre>
 *
 * @param <T> the type of the attribute value
 * @since 1.0
 */
public class SessionAttribute<T> {
    
    /**
     * The session attribute key.
     */
    private final String key;
    
    /**
     * The type of the attribute value (for runtime type checking).
     */
    private final Class<T> type;
    
    /**
     * The default value (may be null).
     */
    private final T defaultValue;
    
    /**
     * Creates a new session attribute definition without a default value.
     *
     * @param key the session attribute key
     * @param type the type of the attribute value
     * @throws NullPointerException if key or type is null
     */
    public SessionAttribute(String key, Class<T> type) {
        this(key, type, null);
    }
    
    /**
     * Creates a new session attribute definition with a default value.
     *
     * @param key the session attribute key
     * @param type the type of the attribute value
     * @param defaultValue the default value (may be null)
     * @throws NullPointerException if key or type is null
     */
    public SessionAttribute(String key, Class<T> type, T defaultValue) {
        this.key = Objects.requireNonNull(key, "Session attribute key must not be null");
        this.type = Objects.requireNonNull(type, "Session attribute type must not be null");
        this.defaultValue = defaultValue;
    }
    
    /**
     * Gets the session attribute key.
     *
     * @return the attribute key
     */
    public String getKey() {
        return key;
    }
    
    /**
     * Gets the type of the attribute value.
     *
     * @return the attribute type
     */
    public Class<T> getType() {
        return type;
    }
    
    /**
     * Gets the default value.
     *
     * @return the default value, or null if not set
     */
    public T getDefaultValue() {
        return defaultValue;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SessionAttribute<?> that = (SessionAttribute<?>) o;
        return Objects.equals(key, that.key);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(key);
    }
    
    @Override
    public String toString() {
        return "SessionAttribute{" +
                "key='" + key + '\'' +
                ", type=" + type.getSimpleName() +
                '}';
    }
}
