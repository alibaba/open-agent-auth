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
package com.alibaba.openagentauth.sample.agent.integration.llm.mock;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Mock LLM Configuration
 * 
 * Configuration class for mock LLM client behavior.
 * Defines strategies for intent matching, parameter extraction, and response generation.
 * 
 * <p>This configuration is loaded from application.yml under the {@code agent.mock} prefix.
 * 
 * @since 1.0
 */
@ConfigurationProperties(prefix = "agent.mock")
public class MockConfig {
    
    /**
     * Whether mock mode is enabled
     */
    private boolean enabled = false;
    
    /**
     * List of mock strategies
     */
    private List<Strategy> strategies = new ArrayList<>();
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
    
    public List<Strategy> getStrategies() {
        return strategies;
    }
    
    public void setStrategies(List<Strategy> strategies) {
        this.strategies = strategies;
    }
    
    /**
     * Mock Strategy
     * 
     * Defines how to handle a specific user intent.
     */
    public static class Strategy {
        /**
         * Strategy name (unique identifier)
         */
        private String name;
        
        /**
         * Intent description
         */
        private String intent;
        
        /**
         * Keywords that trigger this strategy
         */
        private List<String> keywords = new ArrayList<>();
        
        /**
         * Tool server name (if this strategy requires tool calling)
         */
        private String toolServer;
        
        /**
         * Tool name (if this strategy requires tool calling)
         */
        private String toolName;
        
        /**
         * Parameter extraction rules
         */
        private List<ParamRule> paramRules = new ArrayList<>();
        
        /**
         * Response template for success cases
         */
        private String responseTemplate;
        
        /**
         * Response template for error cases
         */
        private String errorTemplate;
        
        /**
         * Whether this strategy requires tool calling
         */
        private boolean noTool = false;
        
        /**
         * Static response for non-tool strategies
         */
        private String response;
        
        public String getName() {
            return name;
        }
        
        public void setName(String name) {
            this.name = name;
        }
        
        public String getIntent() {
            return intent;
        }
        
        public void setIntent(String intent) {
            this.intent = intent;
        }
        
        public List<String> getKeywords() {
            return keywords;
        }
        
        public void setKeywords(List<String> keywords) {
            this.keywords = keywords;
        }
        
        public String getToolServer() {
            return toolServer;
        }
        
        public void setToolServer(String toolServer) {
            this.toolServer = toolServer;
        }
        
        public String getToolName() {
            return toolName;
        }
        
        public void setToolName(String toolName) {
            this.toolName = toolName;
        }
        
        public List<ParamRule> getParamRules() {
            return paramRules;
        }
        
        public void setParamRules(List<ParamRule> paramRules) {
            this.paramRules = paramRules;
        }
        
        public String getResponseTemplate() {
            return responseTemplate;
        }
        
        public void setResponseTemplate(String responseTemplate) {
            this.responseTemplate = responseTemplate;
        }
        
        public String getErrorTemplate() {
            return errorTemplate;
        }
        
        public void setErrorTemplate(String errorTemplate) {
            this.errorTemplate = errorTemplate;
        }
        
        public boolean isNoTool() {
            return noTool;
        }
        
        public void setNoTool(boolean noTool) {
            this.noTool = noTool;
        }
        
        public String getResponse() {
            return response;
        }
        
        public void setResponse(String response) {
            this.response = response;
        }
    }
    
    /**
     * Parameter Extraction Rule
     * 
     * Defines how to extract a parameter from user input.
     */
    public static class ParamRule {
        /**
         * Parameter name in the tool call
         */
        private String param;
        
        /**
         * Source of the parameter value
         */
        private String source;
        
        /**
         * Regex pattern to extract the value
         */
        private String pattern;
        
        /**
         * Default value if extraction fails
         */
        private String defaultValue;
        
        public String getParam() {
            return param;
        }
        
        public void setParam(String param) {
            this.param = param;
        }
        
        public String getSource() {
            return source;
        }
        
        public void setSource(String source) {
            this.source = source;
        }
        
        public String getPattern() {
            return pattern;
        }
        
        public void setPattern(String pattern) {
            this.pattern = pattern;
        }
        
        public String getDefaultValue() {
            return defaultValue;
        }
        
        public void setDefaultValue(String defaultValue) {
            this.defaultValue = defaultValue;
        }
    }
}
