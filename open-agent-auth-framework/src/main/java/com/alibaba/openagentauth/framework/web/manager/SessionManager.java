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

import com.alibaba.openagentauth.core.util.ValidationUtils;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Type-safe session attribute manager.
 * <p>
 * This class provides a unified interface for managing session attributes
 * with compile-time type safety. It eliminates the need for multiple set/get
 * methods for each attribute, preventing method explosion as the application grows.
 * </p>
 * <p>
 * <b>Design Pattern:</b> Generic Type-Safe Accessor Pattern</p>
 * <p>
 * <b>Design Principles:</b></p>
 * <ul>
 *   <li><b>DRY (Don't Repeat Yourself):</b> Single get/set/remove method for all attributes</li>
 *   <li><b>Type Safety:</b> Compile-time type checking via generics</li>
 *   <li><b>Encapsulation:</b> Centralized session attribute access</li>
 * </ul>
 * <p>
 * <b>Usage:</b></p>
 * <pre>
 * // Set attribute
 * SessionManager.setAttribute(session, SessionAttributes.AUTHENTICATED_USER, "user123");
 * 
 * // Get attribute with type safety
 * String userId = SessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER);
 * 
 * // Get attribute with default value
 * String userId = SessionManager.getAttribute(session, SessionAttributes.AUTHENTICATED_USER, "guest");
 * 
 * // Remove attribute
 * SessionManager.removeAttribute(session, SessionAttributes.AUTHENTICATED_USER);
 * 
 * // Check if attribute exists
 * boolean hasUser = SessionManager.hasAttribute(session, SessionAttributes.AUTHENTICATED_USER);
 * 
 * // Fluent API for batch operations
 * SessionManager.with(session)
 *     .set(SessionAttributes.AUTHENTICATED_USER, "user123")
 *     .set(SessionAttributes.ID_TOKEN, token)
 *     .set(SessionAttributes.OAUTH_STATE, state);
 * </pre>
 *
 * @since 1.0
 */
public class SessionManager {
    
    private static final Logger logger = LoggerFactory.getLogger(SessionManager.class);
    
    /**
     * Sets a session attribute with type safety.
     *
     * @param session the HTTP session
     * @param attribute the session attribute definition
     * @param value the value to set
     * @param <T> the type of the attribute value
     * @throws NullPointerException if session or attribute is null
     */
    public static <T> void setAttribute(HttpSession session, SessionAttribute<T> attribute, T value) {
        ValidationUtils.validateNotNull(session, "Session");
        ValidationUtils.validateNotNull(attribute, "Session attribute");
        
        session.setAttribute(attribute.getKey(), value);
        logger.debug("Session attribute set: {}", attribute);
    }
    
    /**
     * Gets a session attribute with type safety.
     *
     * @param session the HTTP session
     * @param attribute the session attribute definition
     * @param <T> the type of the attribute value
     * @return the attribute value, or null if not found
     * @throws NullPointerException if session or attribute is null
     * @throws ClassCastException if the stored value is not of the expected type
     */
    @SuppressWarnings("unchecked")
    public static <T> T getAttribute(HttpSession session, SessionAttribute<T> attribute) {
        ValidationUtils.validateNotNull(session, "Session");
        ValidationUtils.validateNotNull(attribute, "Session attribute");
        
        Object value = session.getAttribute(attribute.getKey());
        if (value == null) {
            return null;
        }
        
        // Type-safe cast
        if (!attribute.getType().isInstance(value)) {
            logger.warn("Session attribute type mismatch: expected={}, actual={}",
                    attribute.getType(), value.getClass());
            return null;
        }
        
        return (T) value;
    }
    
    /**
     * Gets a session attribute with type safety and default value.
     *
     * @param session the HTTP session
     * @param attribute the session attribute definition
     * @param defaultValue the default value to return if attribute is not found
     * @param <T> the type of the attribute value
     * @return the attribute value, or defaultValue if not found
     * @throws NullPointerException if session or attribute is null
     */
    public static <T> T getAttribute(HttpSession session, SessionAttribute<T> attribute, T defaultValue) {
        T value = getAttribute(session, attribute);
        return value != null ? value : defaultValue;
    }
    
    /**
     * Gets a list session attribute and filters elements by type.
     * <p>
     * This method is useful when the session stores a List of mixed types
     * and you need to extract only elements of a specific type.
     * </p>
     * <p>
     * <b>Usage:</b></p>
     * <pre>
     * // Before optimization:
     * List&lt;Object&gt; conversationHistoryObj = SessionManager.getAttribute(session, SessionAttributes.CONVERSATION_HISTORY);
     * List&lt;ChatMessage&gt; conversationHistory = new ArrayList&lt;&gt;();
     * if (conversationHistoryObj != null) {
     *     for (Object obj : conversationHistoryObj) {
     *         if (obj instanceof ChatMessage) {
     *             conversationHistory.add((ChatMessage) obj);
     *         }
     *     }
     * }
     * 
     * // After optimization:
     * List&lt;ChatMessage&gt; conversationHistory = SessionManager.getAttributeAsList(
     *     session, 
     *     SessionAttributes.CONVERSATION_HISTORY, 
     *     ChatMessage.class
     * );
     * </pre>
     *
     * @param session the HTTP session
     * @param attribute the session attribute definition (should be of type List)
     * @param elementType the type of elements to filter from the list
     * @param <E> the element type
     * @return a new list containing only elements of the specified type, or an empty list if attribute is null
     * @throws NullPointerException if session or attribute is null
     */
    @SuppressWarnings("unchecked")
    public static <E> List<E> getAttributeAsList(HttpSession session, SessionAttribute<List> attribute, Class<E> elementType) {
        ValidationUtils.validateNotNull(session, "Session");
        ValidationUtils.validateNotNull(attribute, "Session attribute");
        ValidationUtils.validateNotNull(elementType, "Element type");
        
        List<Object> list = getAttribute(session, attribute);
        if (list == null) {
            return new ArrayList<>();
        }
        
        List<E> result = new ArrayList<>();
        for (Object item : list) {
            if (elementType.isInstance(item)) {
                result.add(elementType.cast(item));
            }
        }
        
        return result;
    }
    
    /**
     * Adds an element to a list session attribute.
     * <p>
     * This method provides a convenient way to add an element to a list stored in session,
     * handling the common pattern of: get list, add element, save back to session.
     * </p>
     * <p>
     * <b>Usage:</b></p>
     * <pre>
     * // Before optimization:
     * List&lt;ChatMessage&gt; conversationHistory = SessionManager.getAttributeAsList(session, SessionAttributes.CONVERSATION_HISTORY, ChatMessage.class);
     * conversationHistory.add(errorMessage);
     * @SuppressWarnings("unchecked")
     * List&lt;Object&gt; conversationHistoryToStore = (List&lt;Object&gt;) (List&lt;?&gt;) conversationHistory;
     * SessionManager.setAttribute(session, SessionAttributes.CONVERSATION_HISTORY, conversationHistoryToStore);
     * 
     * // After optimization:
     * SessionManager.addToList(session, SessionAttributes.CONVERSATION_HISTORY, errorMessage, ChatMessage.class);
     * </pre>
     *
     * @param session the HTTP session
     * @param attribute the session attribute definition (should be of type List)
     * @param element the element to add to the list
     * @param elementType the type of elements in the list
     * @param <E> the element type
     * @throws NullPointerException if session, attribute, or element is null
     */
    @SuppressWarnings("unchecked")
    public static <E> void addToList(HttpSession session, SessionAttribute<List> attribute, E element, Class<E> elementType) {
        ValidationUtils.validateNotNull(session, "Session");
        ValidationUtils.validateNotNull(attribute, "Session attribute");
        ValidationUtils.validateNotNull(element, "Element");
        
        List<Object> list = getAttribute(session, attribute);
        if (list == null) {
            list = new ArrayList<>();
        }
        
        list.add(element);
        setAttribute(session, attribute, list);
        
        logger.debug("Added element to list session attribute: {}", attribute);
    }
    
    /**
     * Removes a session attribute.
     *
     * @param session the HTTP session
     * @param attribute the session attribute definition
     * @param <T> the type of the attribute value
     * @throws NullPointerException if session or attribute is null
     */
    public static <T> void removeAttribute(HttpSession session, SessionAttribute<T> attribute) {
        ValidationUtils.validateNotNull(session, "Session");
        ValidationUtils.validateNotNull(attribute, "Session attribute");
        
        session.removeAttribute(attribute.getKey());
        logger.debug("Session attribute removed: {}", attribute);
    }
    
    /**
     * Checks if a session attribute exists.
     *
     * @param session the HTTP session
     * @param attribute the session attribute definition
     * @param <T> the type of the attribute value
     * @return true if the attribute exists, false otherwise
     * @throws NullPointerException if session or attribute is null
     */
    public static <T> boolean hasAttribute(HttpSession session, SessionAttribute<T> attribute) {
        ValidationUtils.validateNotNull(session, "Session");
        ValidationUtils.validateNotNull(attribute, "Session attribute");
        
        return session.getAttribute(attribute.getKey()) != null;
    }
    
    /**
     * Creates a fluent API session builder for batch operations.
     *
     * @param session the HTTP session
     * @return a fluent session builder
     * @throws NullPointerException if session is null
     */
    public static SessionBuilder with(HttpSession session) {
        ValidationUtils.validateNotNull(session, "Session");
        return new SessionBuilder(session);
    }
    
    /**
     * Fluent API builder for batch session operations.
     * <p>
     * This class provides a convenient way to perform multiple session
     * operations in a chain, improving code readability.
     * </p>
     * <p>
     * <b>Usage:</b></p>
     * <pre>
     * SessionManager.with(session)
     *     .set(SessionAttributes.AUTHENTICATED_USER, "user123")
     *     .set(SessionAttributes.ID_TOKEN, token)
     *     .set(SessionAttributes.OAUTH_STATE, state);
     * </pre>
     */
    public static class SessionBuilder {
        
        private final HttpSession session;
        
        SessionBuilder(HttpSession session) {
            this.session = session;
        }
        
        /**
         * Sets a session attribute.
         *
         * @param attribute the session attribute definition
         * @param value the value to set
         * @param <T> the type of the attribute value
         * @return this builder for method chaining
         */
        public <T> SessionBuilder set(SessionAttribute<T> attribute, T value) {
            SessionManager.setAttribute(session, attribute, value);
            return this;
        }
        
        /**
         * Removes a session attribute.
         *
         * @param attribute the session attribute definition
         * @param <T> the type of the attribute value
         * @return this builder for method chaining
         */
        public <T> SessionBuilder remove(SessionAttribute<T> attribute) {
            SessionManager.removeAttribute(session, attribute);
            return this;
        }
        
        /**
         * Gets the underlying session.
         *
         * @return the HTTP session
         */
        public HttpSession getSession() {
            return session;
        }
    }
}