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
package com.alibaba.openagentauth.framework.exception;

import com.alibaba.openagentauth.core.exception.ErrorCode;
import com.alibaba.openagentauth.core.exception.OpenAgentAuthException;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Base exception for all Framework module exceptions.
 * <p>
 * This exception serves as the root for all exceptions in the Framework module,
 * which handles orchestration-level operations (Agent, AuthorizationServer,
 * ResourceServer, AgentIdentityProvider, etc.). All Framework module exceptions
 * should extend from this class.
 * </p>
 * <p>
 * <b>System Code:</b> 11
 * </p>
 * <p>
 * <b>Error Code Format:</b> OPEN_AGENT_AUTH_11_YYZZ
 * </p>
 * <ul>
 *   <li><b>11</b>: Framework system code</li>
 *   <li><b>YY</b>: Domain code (01=Auth, 02=Token, 03=Validation, 04=OAuth2, etc.)</li>
 *   <li><b>ZZ</b>: Error code (unique within the domain)</li>
 * </ul>
 *
 * @since 1.0
 */
public abstract class FrameworkException extends OpenAgentAuthException {

    /**
     * Constructs a new Framework exception with the specified error code.
     *
     * @param errorCode the error code
     */
    protected FrameworkException(ErrorCode errorCode) {
        super(errorCode.getErrorCode(), errorCode.getMessageTemplate());
    }

    /**
     * Constructs a new Framework exception with the specified error code and parameters.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     */
    protected FrameworkException(ErrorCode errorCode, Object... errorParams) {
        super(errorCode.getErrorCode(), errorCode.formatMessage(errorParams),
              errorParams != null ? Arrays.asList(errorParams) : null, null);
    }

    /**
     * Constructs a new Framework exception with the specified error code, parameters, and context.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     * @param context the context information
     */
    protected FrameworkException(ErrorCode errorCode, List<Object> errorParams,
                               Map<String, Object> context) {
        super(errorCode.getErrorCode(), errorCode.formatMessage(errorParams != null ? errorParams.toArray() : null),
              errorParams, context);
    }

    /**
     * Constructs a new Framework exception with the specified error code and cause.
     *
     * @param errorCode the error code
     * @param cause the cause
     */
    protected FrameworkException(ErrorCode errorCode, Throwable cause) {
        super(errorCode.getErrorCode(), errorCode.getMessageTemplate(), cause);
    }

    /**
     * Constructs a new Framework exception with the specified error code, parameters, and cause.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     * @param cause the cause
     */
    protected FrameworkException(ErrorCode errorCode, Throwable cause, Object... errorParams) {
        super(errorCode.getErrorCode(), errorCode.formatMessage(errorParams),
              errorParams != null ? Arrays.asList(errorParams) : null, null, cause);
    }

    /**
     * Constructs a new Framework exception with the specified error code, parameters, context, and cause.
     *
     * @param errorCode the error code
     * @param errorParams the error parameters (varargs)
     * @param context the context information
     * @param cause the cause
     */
    protected FrameworkException(ErrorCode errorCode, List<Object> errorParams,
                               Map<String, Object> context, Throwable cause) {
        super(errorCode.getErrorCode(), errorCode.formatMessage(errorParams != null ? errorParams.toArray() : null),
              errorParams, context, cause);
    }

}
