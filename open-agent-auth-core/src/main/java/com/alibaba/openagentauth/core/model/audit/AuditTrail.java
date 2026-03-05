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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

import java.util.Objects;

/**
 * Represents a semantic audit trail that establishes a complete, semantically traceable chain
 * from the user's original intent to the system's final executed action in AI Agent scenarios.
 * <p>
 * The audit trail captures the original prompt, rendered operation text, semantic expansion level,
 * user acknowledgment timestamp, and consent interface version to provide a comprehensive
 * audit record of the authorization process.
 * <p>
 * This serves multiple purposes: intent provenance (recording what the user originally said),
 * action interpretation (documenting how the system interpreted the input), semantic transparency
 * (showing whether semantic expansions were applied), user confirmation evidence (including
 * timestamps), and accountability support (enabling post-hoc analysis).
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonDeserialize(builder = AuditTrail.Builder.class)
public class AuditTrail {

    /**
     * Original Prompt Text field.
     * <p>
     * The original text the user said (e.g., "Buy something cheap on Nov 11 night").
     * This field is OPTIONAL.
     * </p>
     */
    @JsonProperty("original_prompt_text")
    private final String originalPromptText;

    /**
     * Rendered Operation Text field.
     * <p>
     * How the system interpreted the input (e.g., "Purchase under $50 during 00:00-06:00").
     * This field is OPTIONAL.
     * </p>
     */
    @JsonProperty("rendered_operation_text")
    private final String renderedOperationText;

    /**
     * Semantic Expansion Level field.
     * <p>
     * Level of semantic expansion applied (e.g., "medium").
     * This field is OPTIONAL.
     * </p>
     */
    @JsonProperty("semantic_expansion_level")
    private final String semanticExpansionLevel;

    /**
     * User Acknowledge Timestamp field.
     * <p>
     * When the user reviewed and confirmed the interpreted action.
     * This field is OPTIONAL.
     * The value MUST conform to ISO 8601 UTC format (e.g., "2025-11-11T10:33:00Z").
     * </p>
     */
    @JsonProperty("user_acknowledge_timestamp")
    private final String userAcknowledgeTimestamp;

    /**
     * Consent Interface Version field.
     * <p>
     * Version of the consent UI used.
     * This field is OPTIONAL.
     * </p>
     */
    @JsonProperty("consent_interface_version")
    private final String consentInterfaceVersion;

    private AuditTrail(Builder builder) {
        this.originalPromptText = builder.originalPromptText;
        this.renderedOperationText = builder.renderedOperationText;
        this.semanticExpansionLevel = builder.semanticExpansionLevel;
        this.userAcknowledgeTimestamp = builder.userAcknowledgeTimestamp;
        this.consentInterfaceVersion = builder.consentInterfaceVersion;
    }

    /**
     * Gets the original prompt text.
     *
     * @return the original prompt text
     */
    public String getOriginalPromptText() {
        return originalPromptText;
    }

    /**
     * Gets the rendered operation text.
     *
     * @return the rendered operation text
     */
    public String getRenderedOperationText() {
        return renderedOperationText;
    }

    /**
     * Gets the semantic expansion level.
     *
     * @return the semantic expansion level
     */
    public String getSemanticExpansionLevel() {
        return semanticExpansionLevel;
    }

    /**
     * Gets the user acknowledge timestamp.
     *
     * @return the user acknowledge timestamp in ISO 8601 format
     */
    public String getUserAcknowledgeTimestamp() {
        return userAcknowledgeTimestamp;
    }

    /**
     * Gets the consent interface version.
     *
     * @return the consent interface version
     */
    public String getConsentInterfaceVersion() {
        return consentInterfaceVersion;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditTrail auditTrail = (AuditTrail) o;
        return Objects.equals(originalPromptText, auditTrail.originalPromptText) &&
               Objects.equals(renderedOperationText, auditTrail.renderedOperationText) &&
               Objects.equals(semanticExpansionLevel, auditTrail.semanticExpansionLevel) &&
               Objects.equals(userAcknowledgeTimestamp, auditTrail.userAcknowledgeTimestamp) &&
               Objects.equals(consentInterfaceVersion, auditTrail.consentInterfaceVersion);
    }

    @Override
    public int hashCode() {
        return Objects.hash(originalPromptText, renderedOperationText, semanticExpansionLevel,
                          userAcknowledgeTimestamp, consentInterfaceVersion);
    }

    @Override
    public String toString() {
        return "AuditTrail{" +
                "originalPromptText='" + originalPromptText + '\'' +
                ", renderedOperationText='" + renderedOperationText + '\'' +
                ", semanticExpansionLevel='" + semanticExpansionLevel + '\'' +
                ", userAcknowledgeTimestamp='" + userAcknowledgeTimestamp + '\'' +
                ", consentInterfaceVersion='" + consentInterfaceVersion + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link AuditTrail}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AuditTrail}.
     */
    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder {

        /**
         * Fields for {@link AuditTrail}.
         */
        private String originalPromptText;
        private String renderedOperationText;
        private String semanticExpansionLevel;
        private String userAcknowledgeTimestamp;
        private String consentInterfaceVersion;

        /**
         * Sets the original prompt text.
         *
         * @param originalPromptText the original prompt text
         * @return this builder instance
         */
        @JsonProperty("original_prompt_text")
        public Builder originalPromptText(String originalPromptText) {
            this.originalPromptText = originalPromptText;
            return this;
        }

        /**
         * Sets the rendered operation text.
         *
         * @param renderedOperationText the rendered operation text
         * @return this builder instance
         */
        @JsonProperty("rendered_operation_text")
        public Builder renderedOperationText(String renderedOperationText) {
            this.renderedOperationText = renderedOperationText;
            return this;
        }

        /**
         * Sets the semantic expansion level.
         *
         * @param semanticExpansionLevel the semantic expansion level
         * @return this builder instance
         */
        @JsonProperty("semantic_expansion_level")
        public Builder semanticExpansionLevel(String semanticExpansionLevel) {
            this.semanticExpansionLevel = semanticExpansionLevel;
            return this;
        }

        /**
         * Sets the user acknowledgment timestamp.
         * <p>
         * The value MUST conform to ISO 8601 UTC format (e.g., "2025-11-11T10:33:00Z").
         * </p>
         *
         * @param userAcknowledgeTimestamp the user acknowledgment timestamp in ISO 8601 format
         * @return this builder instance
         */
        @JsonProperty("user_acknowledge_timestamp")
        public Builder userAcknowledgeTimestamp(String userAcknowledgeTimestamp) {
            this.userAcknowledgeTimestamp = userAcknowledgeTimestamp;
            return this;
        }

        /**
         * Sets the consent interface version.
         *
         * @param consentInterfaceVersion the consent interface version
         * @return this builder instance
         */
        @JsonProperty("consent_interface_version")
        public Builder consentInterfaceVersion(String consentInterfaceVersion) {
            this.consentInterfaceVersion = consentInterfaceVersion;
            return this;
        }

        /**
         * Builds the {@link AuditTrail}.
         *
         * @return the built audit trail
         */
        public AuditTrail build() {
            return new AuditTrail(this);
        }
    }
}