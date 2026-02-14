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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Response Generator
 * 
 * Generates natural language responses based on tool execution results.
 * Supports template-based response generation with variable substitution.
 * 
 * @since 1.0
 */
public class ResponseGenerator {
    
    private static final Logger log = LoggerFactory.getLogger(ResponseGenerator.class);
    
    /**
     * Generate a success response based on the template and tool result.
     * 
     * @param template the response template
     * @param toolResult the tool execution result
     * @param params the parameters used in the tool call
     * @return the generated response
     */
    public String generateSuccessResponse(String template, String toolResult, Map<String, Object> params) {
        if (template == null || template.isBlank()) {
            return "Operation completed successfully. Result: " + toolResult;
        }
        
        try {
            String response = template;
            
            // Replace {result} with tool result
            response = response.replace("{result}", toolResult != null ? toolResult : "");
            
            // Replace parameter placeholders
            if (params != null) {
                for (Map.Entry<String, Object> entry : params.entrySet()) {
                    String placeholder = "{" + entry.getKey() + "}";
                    String value = entry.getValue() != null ? entry.getValue().toString() : "";
                    response = response.replace(placeholder, value);
                }
            }
            
            return response;
        } catch (Exception e) {
            log.error("Failed to generate success response", e);
            return "Operation completed successfully. Result: " + toolResult;
        }
    }
    
    /**
     * Generate an error response based on the template and error message.
     * 
     * @param template the error response template
     * @param errorMessage the error message
     * @return the generated error response
     */
    public String generateErrorResponse(String template, String errorMessage) {
        if (template == null || template.isBlank()) {
            return "Operation failed. Error: " + errorMessage;
        }
        
        try {
            return template.replace("{error}", errorMessage != null ? errorMessage : "Unknown error");
        } catch (Exception e) {
            log.error("Failed to generate error response", e);
            return "Operation failed. Error: " + errorMessage;
        }
    }
}
