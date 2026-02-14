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

/**
 * Exception thrown when a policy is not found in the registry.
 * <p>
 * This exception is raised when attempting to retrieve, evaluate, or update
 * a policy that does not exist in the policy registry. This can occur when:
 * <ul>
 *   <li>The policy ID is invalid or does not exist</li>
 *   <li>The policy has been deleted</li>
 *   <li>The policy has expired and been purged</li>
 * </ul>
 * </p>
 *
 * @see PolicyException
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public class PolicyNotFoundException extends PolicyException {

    /**
     * The error code for this exception.
     */
    private static final PolicyErrorCode ERROR_CODE = PolicyErrorCode.POLICY_NOT_FOUND;

    /**
     * Creates a new PolicyNotFoundException with the specified message.
     *
     * @param message the error message
     */
    public PolicyNotFoundException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Creates a new PolicyNotFoundException with the specified message and cause.
     *
     * @param message the error message
     * @param cause the cause
     */
    public PolicyNotFoundException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }
}
