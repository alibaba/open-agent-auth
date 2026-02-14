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
package com.alibaba.openagentauth.core.model.audit;

/**
 * Enumeration of audit event types.
 * <p>
 * This enum defines the various types of audit events that can occur
 * in the Agent Operation Authorization framework, providing categorization
 * for audit records and enabling filtering and analysis.
 * </p>
 * <p>
 * <b>Event Categories:</b></p>
 * <ul>
 *   <li><b>AUTHORIZATION:</b> Events related to authorization decisions</li>
 *   <li><b>EVALUATION:</b> Events related to policy evaluation</li>
 *   <li><b>DELEGATION:</b> Events related to agent-to-agent delegation</li>
 *   <li><b>ACCESS:</b> Events related to resource access</li>
 *   <li><b>ERROR:</b> Events related to system errors and failures</li>
 *   <li><b>SECURITY:</b> Events related to security incidents</li>
 * </ul>
 * </p>
 *
 * @see AuditEvent
 * @see AuditSeverity
 */
public enum AuditEventType {

    /**
     * Authorization events.
     * <p>
     * Events related to authorization decisions, including authorization requests,
     * grants, denials, and revocations.
     * </p>
     */
    AUTHORIZATION_REQUEST,
    AUTHORIZATION_GRANTED,
    AUTHORIZATION_DENIED,
    AUTHORIZATION_REVOKED,

    /**
     * Policy evaluation events.
     * <p>
     * Events related to policy evaluation, including evaluation requests,
     * results, and policy registration.
     * </p>
     */
    POLICY_EVALUATION_REQUEST,
    POLICY_EVALUATION_SUCCESS,
    POLICY_EVALUATION_FAILURE,
    POLICY_REGISTERED,
    POLICY_UPDATED,
    POLICY_DELETED,

    /**
     * Delegation events.
     * <p>
     * Events related to agent-to-agent delegation, including delegation requests,
     * grants, and chain updates.
     * </p>
     */
    DELEGATION_REQUEST,
    DELEGATION_GRANTED,
    DELEGATION_DENIED,
    DELEGATION_CHAIN_UPDATED,

    /**
     * Resource access events.
     * <p>
     * Events related to resource access attempts, including successful and failed access.
     * </p>
     */
    RESOURCE_ACCESS_REQUEST,
    RESOURCE_ACCESS_GRANTED,
    RESOURCE_ACCESS_DENIED,

    /**
     * Error events.
     * <p>
     * Events related to system errors and failures, including evaluation errors,
     * validation errors, and system failures.
     * </p>
     */
    EVALUATION_ERROR,
    VALIDATION_ERROR,
    SYSTEM_ERROR,

    /**
     * Security events.
     * <p>
     * Events related to security incidents, including authentication failures,
     * authorization bypass attempts, and suspicious activities.
     * </p>
     */
    AUTHENTICATION_FAILURE,
    AUTHORIZATION_BYPASS_ATTEMPT,
    SUSPICIOUS_ACTIVITY,
    SECURITY_VIOLATION
}
