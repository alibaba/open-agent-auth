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
package com.alibaba.openagentauth.core.protocol.wimse.workload.client;

import com.alibaba.openagentauth.core.exception.workload.WorkloadCreationException;
import com.alibaba.openagentauth.core.exception.workload.WorkloadNotFoundException;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitResponse;
import com.alibaba.openagentauth.core.protocol.wimse.workload.model.IssueWitRequest;

/**
 * HTTP client for Agent Identity Provider.
 * <p>
 * This interface defines the contract for calling Agent IDP services via HTTP,
 * following standard RESTful protocol design. It enables distributed architecture
 * where Agent Provider calls Agent IDP as a remote service.
 * </p>
 * <p>
 * <b>Usage:</b></p>
 * <pre>
 * AgentIdpHttpClient client = ...;
 * 
 * // Issue WIT with automatic workload management
 * IssueWitRequest request = IssueWitRequest.builder()
 *     .context(context)
 *     .proposal(proposal)
 *     .publicKey(publicKey)
 *     .build();
 * IssueWitResponse response = client.issueWit(request);
 * 
 * // Revoke workload
 * client.revokeWorkload(workloadId);
 * </pre>
 *
 * @since 1.0
 */
public interface WorkloadClient {

    /**
     * Issues a Workload Identity Token (WIT) with automatic workload management.
     * <p>
     * This is a convenience method that combines workload retrieval/creation and WIT issuance
     * into a single HTTP call. It simplifies the developer experience by abstracting away
     * the workload lifecycle management details.
     * </p>
     * 
     * <h3>Workflow:</h3>
     * <ul>
     *   <li><b>Step 1:</b> Agent IDP validates ID Token and extracts user identity</li>
     *   <li><b>Step 2:</b> Agent IDP finds an existing active workload for the same user + client binding</li>
     *   <li><b>Step 3:</b> If no valid workload exists, Agent IDP creates a new one</li>
     *   <li><b>Step 4:</b> Agent IDP issues a WIT with independent expiration time</li>
     * </ul>
     * 
     * <h3>Design Principles:</h3>
     * <ul>
     *   <li><b>Separation of Concerns:</b> Workload lifecycle is managed independently from token lifecycle</li>
     *   <li><b>Resource Efficiency:</b> Reuses existing workloads when possible to reduce overhead</li>
     *   <li><b>Security:</b> Short-lived WITs minimize the impact of token leakage</li>
     *   <li><b>Flexibility:</b> Workload binding strategy can be customized without changing the interface</li>
     * </ul>
     * 
     * @param request the issue WIT request containing operation context and agent-user binding proposal
     * @return the issued WIT response
     * @throws WorkloadCreationException if workload creation fails
     * @throws WorkloadNotFoundException if the workload is not found
     * @since 1.0
     */
    IssueWitResponse issueWit(IssueWitRequest request)
            throws WorkloadCreationException, WorkloadNotFoundException;

    /**
     * Revokes an agent workload via HTTP.
     * <p>
     * This method calls the Agent IDP's REST API to revoke the specified agent
     * workload, invalidating any tokens issued for it.
     * </p>
     *
     * @param workloadId the workload identifier
     * @throws WorkloadNotFoundException if the workload is not found
     */
    void revokeWorkload(String workloadId) throws WorkloadNotFoundException;
}