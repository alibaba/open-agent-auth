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

import com.alibaba.openagentauth.core.exception.CoreException;

/**
 * Base exception for all binding-related errors.
 * <p>
 * This exception serves as the parent class for all binding-related exceptions
 * in the Agent Operation Authorization framework. It provides a common base
 * for catching and handling binding errors.
 * </p>
 * <p>
 * Binding represents the relationship between user identities and workload identities.
 * Common binding-related exceptions include:
 * <ul>
 *   <li>BindingNotFoundException - Binding not found in store</li>
 *   <li>BindingValidationException - Binding validation errors</li>
 *   <li>BindingExpiredException - Binding has expired</li>
 * </ul>
 * </p>
 * <p>
 * <b>Domain Code:</b> 07
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_07ZZ
 * </p>
 *
 * @see BindingNotFoundException
 * @since 1.0
 */
public abstract class BindingException extends CoreException {

    /**
     * The binding instance ID associated with this exception, if any.
     */
    private final String bindingInstanceId;

    /**
     * Constructs a new Binding exception with the specified error code and parameters.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected BindingException(BindingErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
        this.bindingInstanceId = null;
    }

    /**
     * Constructs a new Binding exception with the specified error code, binding instance ID, and parameters.
     *
     * @param bindingInstanceId the binding instance ID
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected BindingException(String bindingInstanceId, BindingErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
        this.bindingInstanceId = bindingInstanceId;
    }

    /**
     * Constructs a new Binding exception with the specified error code, cause, and parameters.
     *
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected BindingException(BindingErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode, cause, errorParams);
        this.bindingInstanceId = null;
    }

    /**
     * Constructs a new Binding exception with the specified error code, binding instance ID, cause, and parameters.
     *
     * @param bindingInstanceId the binding instance ID
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected BindingException(String bindingInstanceId, BindingErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode, cause, errorParams);
        this.bindingInstanceId = bindingInstanceId;
    }

    /**
     * Gets the binding instance ID associated with this exception.
     *
     * @return the binding instance ID, or null if not available
     */
    public String getBindingInstanceId() {
        return bindingInstanceId;
    }
}