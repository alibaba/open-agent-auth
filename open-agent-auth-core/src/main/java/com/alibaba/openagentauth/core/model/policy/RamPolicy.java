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
package com.alibaba.openagentauth.core.model.policy;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * RAM (Resource Access Management) policy model.
 * <p>
 * Similar to AWS IAM and Alibaba Cloud RAM policy structure.
 * </p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RamPolicy {
    
    @JsonProperty("version")
    private final String version;
    
    @JsonProperty("statement")
    private final List<RamStatement> statements;
    
    @JsonCreator
    private RamPolicy(
        @JsonProperty("version") String version,
        @JsonProperty("statement") List<RamStatement> statements
    ) {
        this.version = version != null ? version : "1.0";
        this.statements = statements != null ? Collections.unmodifiableList(statements) : List.of();
    }
    
    public String getVersion() {
        return version;
    }
    
    public List<RamStatement> getStatements() {
        return statements;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RamPolicy ramPolicy = (RamPolicy) o;
        return Objects.equals(version, ramPolicy.version) &&
                Objects.equals(statements, ramPolicy.statements);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(version, statements);
    }
    
    @Override
    public String toString() {
        return "RamPolicy{" +
                "version='" + version + '\'' +
                ", statements=" + statements +
                '}';
    }
    
    /**
     * RAM statement.
     */
    public static class RamStatement {
        
        @JsonProperty("effect")
        private final Effect effect;
        
        @JsonProperty("action")
        private final List<String> actions;
        
        @JsonProperty("resource")
        private final List<String> resources;
        
        @JsonProperty("condition")
        private final RamCondition condition;
        
        @JsonCreator
        private RamStatement(
            @JsonProperty("effect") Effect effect,
            @JsonProperty("action") List<String> actions,
            @JsonProperty("resource") List<String> resources,
            @JsonProperty("condition") RamCondition condition
        ) {
            this.effect = effect != null ? effect : Effect.ALLOW;
            this.actions = actions != null ? Collections.unmodifiableList(actions) : List.of();
            this.resources = resources != null ? Collections.unmodifiableList(resources) : List.of();
            this.condition = condition;
        }
        
        public Effect getEffect() {
            return effect;
        }
        
        public List<String> getActions() {
            return actions;
        }
        
        public List<String> getResources() {
            return resources;
        }
        
        public RamCondition getCondition() {
            return condition;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RamStatement that = (RamStatement) o;
            return effect == that.effect &&
                    Objects.equals(actions, that.actions) &&
                    Objects.equals(resources, that.resources) &&
                    Objects.equals(condition, that.condition);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(effect, actions, resources, condition);
        }
        
        @Override
        public String toString() {
            return "RamStatement{" +
                    "effect=" + effect +
                    ", actions=" + actions +
                    ", resources=" + resources +
                    ", condition=" + condition +
                    '}';
        }
    }
    
    /**
     * RAM effect enum.
     */
    public enum Effect {
        ALLOW, DENY
    }
    
    /**
     * RAM condition.
     */
    public static class RamCondition {
        
        @JsonProperty("operator")
        private final String operator;
        
        @JsonProperty("key")
        private final String key;
        
        @JsonProperty("value")
        private final Object value;
        
        @JsonCreator
        private RamCondition(
            @JsonProperty("operator") String operator,
            @JsonProperty("key") String key,
            @JsonProperty("value") Object value
        ) {
            this.operator = operator;
            this.key = key;
            this.value = value;
        }
        
        public String getOperator() {
            return operator;
        }
        
        public String getKey() {
            return key;
        }
        
        public Object getValue() {
            return value;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            RamCondition that = (RamCondition) o;
            return Objects.equals(operator, that.operator) &&
                    Objects.equals(key, that.key) &&
                    Objects.equals(value, that.value);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(operator, key, value);
        }
        
        @Override
        public String toString() {
            return "RamCondition{" +
                    "operator='" + operator + '\'' +
                    ", key='" + key + '\'' +
                    ", value=" + value +
                    '}';
        }
    }
}
