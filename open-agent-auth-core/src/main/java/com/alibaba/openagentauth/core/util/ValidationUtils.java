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

/**
 * Utility class for parameter validation in the core module.
 * <p>
 * This class provides static utility methods for validating method parameters,
 * following the fail-fast principle to detect invalid inputs early.
 * </p>
 * <p>
 * <b>Usage Example:</b></p>
 * <pre>{@code
 * public MyClass(String name, Object obj) {
 *     this.name = ValidationUtils.validateNotEmpty(name, "name");
 *     this.obj = ValidationUtils.validateNotNull(obj, "obj");
 * }
 * }</pre>
 *
 * @since 1.0
 */
public final class ValidationUtils {

    /**
     * Private constructor to prevent instantiation.
     */
    private ValidationUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    /**
     * Validates that the given object is not null.
     *
     * @param <T> the type of the object
     * @param obj the object to validate
     * @param paramName the parameter name for error message
     * @return the validated object
     * @throws IllegalArgumentException if the object is null
     */
    public static <T> T validateNotNull(T obj, String paramName) {
        if (obj == null) {
            throw new IllegalArgumentException(paramName + " cannot be null");
        }
        return obj;
    }

    /**
     * Validates that the given string is not null or empty.
     * <p>
     * This method also checks that the string is not blank (contains only whitespace).
     * </p>
     *
     * @param str the string to validate
     * @param paramName the parameter name for error message
     * @return the validated string
     * @throws IllegalArgumentException if the string is null or empty
     */
    public static String validateNotEmpty(String str, String paramName) {
        if (isNullOrEmpty(str)) {
            throw new IllegalArgumentException(paramName + " cannot be null or empty");
        }
        return str;
    }

    /**
     * Checks if the given string is null or empty.
     * <p>
     * This method also checks that the string is not blank (contains only whitespace).
     * </p>
     *
     * @param str the string to check
     * @return true if the string is null or empty (after trimming), false otherwise
     */
    public static boolean isNullOrEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }

    /**
     * Checks if the given object is null.
     *
     * @param obj the object to check
     * @return true if the object is null, false otherwise
     */
    public static boolean isNull(Object obj) {
        return obj == null;
    }
}
