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
package com.alibaba.openagentauth.core.exception.policy;

import com.alibaba.openagentauth.core.exception.CoreException;

/**
 * Base exception for all policy-related errors.
 * <p>
 * This exception serves as the parent class for all policy-related exceptions
 * in the Agent Operation Authorization framework. It provides a common base
 * for catching and handling policy errors.
 * </p>
 * <p>
 * Common policy-related exceptions include:
 * <ul>
 *   <li>{@link PolicyValidationException} - Policy syntax or semantic validation errors</li>
 *   <li>{@link PolicyNotFoundException} - Policy not found in registry</li>
 *   <li>{@link PolicyEvaluationException} - Policy evaluation runtime errors</li>
 *   <li>{@link PolicyRegistrationException} - Policy registration errors</li>
 * </ul>
 * </p>
 * <p>
 * <b>Domain Code:</b> 05
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_10_05ZZ
 * </p>
 *
 * @see PolicyValidationException
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public abstract class PolicyException extends CoreException {

    /**
     * The policy ID associated with this exception, if any.
     */
    private final String policyId;

    /**
     * Constructs a new Policy exception with the specified error code and parameters.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected PolicyException(PolicyErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
        this.policyId = null;
    }

    /**
     * Constructs a new Policy exception with the specified error code, policy ID, and parameters.
     *
     * @param policyId    the policy ID
     * @param errorCode   the error code
     * @param errorParams the error parameters (varargs)
     */
    protected PolicyException(String policyId, PolicyErrorCode errorCode, Object... errorParams) {
        super(errorCode, errorParams);
        this.policyId = policyId;
    }

    /**
     * Constructs a new Policy exception with the specified error code, cause, and parameters.
     *
     * @param errorCode the error code
     * @param cause the cause
     * @param errorParams the error parameters (varargs)
     */
    protected PolicyException(PolicyErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode, cause, errorParams);
        this.policyId = null;
    }

    /**
     * Constructs a new Policy exception with the specified error code, policy ID, cause, and parameters.
     *
     * @param policyId    the policy ID
     * @param errorCode   the error code
     * @param cause       the cause
     * @param errorParams the error parameters (varargs)
     */
    protected PolicyException(String policyId, PolicyErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode, cause, errorParams);
        this.policyId = policyId;
    }

    /**
     * Gets the policy ID associated with this exception.
     *
     * @return the policy ID, or null if not available
     */
    public String getPolicyId() {
        return policyId;
    }
}
