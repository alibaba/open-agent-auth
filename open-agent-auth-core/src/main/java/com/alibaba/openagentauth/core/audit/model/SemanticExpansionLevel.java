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
package com.alibaba.openagentauth.core.audit.model;

/**
 * Defines the level of semantic expansion applied when rendering operation text.
 * <p>
 * According to draft-liu-agent-operation-authorization-01 Section 4 (auditTrail),
 * the {@code semanticExpansionLevel} field indicates whether semantic expansions
 * or default values were applied during the rendering process.
 * </p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">
 *     draft-liu-agent-operation-authorization-01</a>
 * @since 1.0
 */
public enum SemanticExpansionLevel {

    /**
     * No semantic expansion was applied.
     * The rendered text is a direct representation of the original input without interpretation.
     */
    NONE("none"),

    /**
     * Minimal semantic expansion (basic formatting or normalization).
     * The rendered text closely mirrors the original input with minor formatting adjustments.
     */
    LOW("low"),

    /**
     * Moderate semantic expansion (interpretation of ambiguous terms).
     * The rendered text includes some interpretation of the original input to clarify intent.
     */
    MEDIUM("medium"),

    /**
     * Significant semantic expansion (substantial interpretation and additional context).
     * The rendered text includes substantial interpretation, inferred defaults, or added context
     * beyond what the user explicitly stated.
     */
    HIGH("high");

    /**
     * The string representation of this expansion level, used in the AOAT {@code auditTrail} claim.
     */
    private final String value;

    /**
     * Constructs a semantic expansion level with the given string value.
     *
     * @param value the string representation of this level
     */
    SemanticExpansionLevel(String value) {
        this.value = value;
    }

    /**
     * Returns the string representation of this expansion level.
     *
     * @return the expansion level value (e.g., "none", "low", "medium", "high")
     */
    public String getValue() {
        return value;
    }

    /**
     * Returns the string representation of this expansion level.
     *
     * @return the expansion level value
     */
    @Override
    public String toString() {
        return value;
    }

}
