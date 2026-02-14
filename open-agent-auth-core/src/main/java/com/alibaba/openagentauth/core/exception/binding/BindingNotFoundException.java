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
package com.alibaba.openagentauth.core.exception.binding;

/**
 * Exception thrown when a binding instance is not found.
 * <p>
 * This exception is raised when attempting to retrieve, validate, or operate on
 * a binding instance that does not exist in the store. This can occur when:
 * <ul>
 *   <li>The binding instance ID is invalid or does not exist</li>
 *   <li>The binding has been deleted</li>
 *   <li>The binding has expired and been purged</li>
 * </ul>
 * </p>
 *
 * @see BindingException
 * @since 1.0
 */
public class BindingNotFoundException extends BindingException {

    /**
     * The error code for this exception.
     */
    private static final BindingErrorCode ERROR_CODE = BindingErrorCode.BINDING_NOT_FOUND;

    /**
     * Creates a new BindingNotFoundException with the specified binding instance ID.
     *
     * @param bindingInstanceId the binding instance ID
     */
    public BindingNotFoundException(String bindingInstanceId) {
        super(bindingInstanceId, ERROR_CODE, bindingInstanceId);
    }

    /**
     * Creates a new BindingNotFoundException with the specified message and cause.
     *
     * @param bindingInstanceId the binding instance ID
     * @param cause the cause
     */
    public BindingNotFoundException(String bindingInstanceId, Throwable cause) {
        super(bindingInstanceId, ERROR_CODE, cause, bindingInstanceId);
    }
}
