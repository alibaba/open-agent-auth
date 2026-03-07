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

import com.alibaba.openagentauth.core.audit.model.OperationTextRenderContext;
import com.alibaba.openagentauth.core.audit.model.OperationTextRenderResult;

/**
 * Strategy interface for rendering human-readable operation text from agent operation proposals.
 * <p>
 * According to draft-liu-agent-operation-authorization-01 Section 4, the Authorization Server
 * generates a {@code renderedText} and {@code renderedOperationText} that describe the authorized
 * operation in a human-readable format. These texts are included in the
 * {@code context} and {@code auditTrail} claims of the Agent Operation Authorization Token (AOAT).
 * </p>
 * <p>
 * This interface follows the <b>Strategy Pattern</b> (GoF) to decouple the rendering logic
 * from the token generation process, enabling multiple rendering strategies:
 * </p>
 * <ul>
 *   <li><b>Pattern-based rendering</b>: Extracts structured information from Rego policies
 *       and generates text using predefined templates</li>
 *   <li><b>LLM-based rendering</b>: Uses a large language model to intelligently interpret
 *       policies and generate natural-language descriptions</li>
 *   <li><b>Custom rendering</b>: Allows developers to implement their own rendering logic</li>
 * </ul>
 * <p>
 * The rendered text serves the Semantic Audit Trail purposes defined in the specification:
 * </p>
 * <ol>
 *   <li><b>Intent Provenance</b>: Records what the user originally said</li>
 *   <li><b>Action Interpretation</b>: Documents how the system interpreted the input</li>
 *   <li><b>Semantic Transparency</b>: Shows whether semantic expansions were applied</li>
 *   <li><b>User Confirmation Evidence</b>: Provides proof of authorization</li>
 *   <li><b>Accountability Support</b>: Enables post-hoc analysis</li>
 * </ol>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
 *     draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
@FunctionalInterface
public interface OperationTextRenderer {

    /**
     * Renders a human-readable description of the authorized operation.
     * <p>
     * This method transforms the operation proposal policy, original user prompt,
     * and contextual information into a clear, user-friendly text description.
     * The rendered text is used in both the consent UI (for user review) and
     * the AOAT (for audit trail purposes).
     * </p>
     * <p>
     * The result includes both the rendered text and the semantic expansion level,
     * which are required for the {@code auditTrail} claim in the AOAT.
     * </p>
     *
     * @param context the rendering context containing all relevant information
     * @return the render result containing the text and semantic expansion level, never null
     */
    OperationTextRenderResult render(OperationTextRenderContext context);

}
