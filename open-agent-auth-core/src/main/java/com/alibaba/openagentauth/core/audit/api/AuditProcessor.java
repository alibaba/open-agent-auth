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
package com.alibaba.openagentauth.core.audit.api;

import com.alibaba.openagentauth.core.exception.audit.AuditProcessingException;
import com.alibaba.openagentauth.core.model.audit.AuditEvent;

/**
 * Interface for processing audit events.
 * <p>
 * This interface defines the contract for processing audit events after
 * they have been stored. Implementations can perform various operations
 * such as enrichment, transformation, notification, alerting, or integration
 * with external systems.
 * </p>
 * <p>
 * <b>Design Pattern:</b></p>
 * <ul>
 *   <li><b>Strategy Pattern:</b> Different processors can be plugged into
 *       the audit pipeline</li>
 *   <li><b>Chain of Responsibility:</b> Multiple processors can be chained
 *       together in a processing pipeline</li>
 * </ul>
 * </p>
 * <p>
 * <b>Implementation Considerations:</b></p>
 * <ul>
 *   <li>Implementations should handle processing failures gracefully</li>
 *   <li>Consider implementing retry logic for transient failures</li>
 *   <li>Processors should be idempotent where possible</li>
 *   <li>Implementations should be thread-safe for concurrent processing</li>
 * </ul>
 * </p>
 *
 * @see AuditEvent
 * @see AuditService
 */
public interface AuditProcessor {

    /**
     * Processes an audit event.
     * <p>
     * This method should handle processing failures gracefully, potentially
     * implementing retry logic or fallback mechanisms. Failures in processing
     * should not prevent the event from being stored.
     * </p>
     *
     * @param event the audit event to process
     * @throws AuditProcessingException if processing fails
     */
    void process(AuditEvent event) throws AuditProcessingException;

    /**
     * Gets the priority of this processor.
     * <p>
     * Processors with higher priority values are executed first in the
     * processing pipeline.
     * </p>
     *
     * @return the priority value (higher values indicate higher priority)
     */
    default int getPriority() {
        return 0;
    }

}
