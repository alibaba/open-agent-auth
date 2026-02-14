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
package com.alibaba.openagentauth.core.policy.evaluator;

import com.alibaba.openagentauth.core.exception.policy.PolicyEvaluationException;
import com.alibaba.openagentauth.core.exception.policy.PolicyNotFoundException;
import com.alibaba.openagentauth.core.model.policy.OpaPolicy;
import com.alibaba.openagentauth.core.model.policy.Policy;
import com.alibaba.openagentauth.core.model.policy.PolicyEvaluationResult;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.policy.api.PolicyRegistry;
import com.alibaba.openagentauth.core.policy.evaluator.opa.DefaultOpaHttpClient;
import com.alibaba.openagentauth.core.policy.evaluator.opa.OpaBodyHandler;
import com.alibaba.openagentauth.core.policy.evaluator.opa.OpaHttpClient;
import com.alibaba.openagentauth.core.policy.evaluator.opa.OpaHttpResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * OPA REST API-based implementation of {@link PolicyEvaluator}.
 * <p>
 * This evaluator connects to an external Open Policy Agent (OPA) server via REST API
 * to evaluate Rego policies. It provides full OPA functionality and is suitable for
 * production environments requiring comprehensive policy evaluation capabilities.
 * </p>
 * <p>
 * <b>Core Responsibilities:</b></p>
 * <ul>
 *   <li>Evaluate policies using OPA's REST API</li>
 *   <li>Support full Rego language specification</li>
 *   <li>Provide detailed evaluation results with reasoning</li>
 *   <li>Handle network failures and retries</li>
 * </ul>
 * </p>
 * <p>
 * <b>Implementation Details:</b></p>
 * <ul>
 *   <li>Uses Java 11+ HttpClient for HTTP communication</li>
 *   <li>Supports configurable OPA server endpoint</li>
 *   <li>Provides connection pooling and timeout management</li>
 *   <li>Thread-safe implementation</li>
 * </ul>
 * </p>
 * <p>
 * <b>Requirements:</b></p>
 * <ul>
 *   <li>OPA server must be running and accessible</li>
 *   <li>Policies must be registered with OPA before evaluation</li>
 *   <li>Network connectivity to OPA server is required</li>
 * </ul>
 * </p>
 * <p>
 * <b>Configuration:</b></p>
 * <pre>
 * OpaRestPolicyEvaluator evaluator = new OpaRestPolicyEvaluator(
 *     policyRegistry,
 *     "http://localhost:8181",
 *     Duration.ofSeconds(10)
 * );
 * </pre>
 * </p>
 *
 * @see PolicyEvaluator
 * @see LightweightPolicyEvaluator
 * @see <a href="https://www.openpolicyagent.org/docs/latest/rest-api/">OPA REST API</a>
 * @see <a href="https://datatracker.ietf.org/doc/draft-liu-agent-operation-authorization/">draft-liu-agent-operation-authorization-01</a>
 */
public class OpaRestPolicyEvaluator implements PolicyEvaluator {

    private static final Logger logger = LoggerFactory.getLogger(OpaRestPolicyEvaluator.class);

    private final PolicyRegistry policyRegistry;
    private final OpaHttpClient httpClient;
    private final String opaBaseUrl;
    private final ObjectMapper objectMapper;
    private final Duration timeout;

    /**
     * Default timeout duration.
     */
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    /**
     * Creates a new OpaRestPolicyEvaluator with custom OPA server URL.
     *
     * @param policyRegistry the policy registry
     * @param opaBaseUrl     the OPA server base URL
     */
    public OpaRestPolicyEvaluator(PolicyRegistry policyRegistry, String opaBaseUrl) {
        this(policyRegistry, opaBaseUrl, DEFAULT_TIMEOUT);
    }

    /**
     * Creates a new OpaRestPolicyEvaluator with custom settings.
     *
     * @param policyRegistry the policy registry
     * @param opaBaseUrl     the OPA server base URL
     * @param timeout        the request timeout
     */
    public OpaRestPolicyEvaluator(PolicyRegistry policyRegistry, String opaBaseUrl, Duration timeout) {
        this(policyRegistry, opaBaseUrl, timeout, new DefaultOpaHttpClient(timeout));
        logger.info("OpaRestPolicyEvaluator initialized with OPA URL: {}", opaBaseUrl);
    }

    /**
     * Creates a new OpaRestPolicyEvaluator with injected OpaHttpClient.
     * <p>
     * This constructor is primarily intended for testing purposes, allowing
     * a mock OpaHttpClient to be injected for unit testing without requiring
     * a real OPA server.
     * </p>
     *
     * @param policyRegistry the policy registry
     * @param opaBaseUrl     the OPA server base URL
     * @param timeout        the request timeout
     * @param httpClient     the OpaHttpClient to use for HTTP communication
     */
    OpaRestPolicyEvaluator(PolicyRegistry policyRegistry, String opaBaseUrl, Duration timeout, OpaHttpClient httpClient) {
        this.policyRegistry = policyRegistry;
        this.opaBaseUrl = opaBaseUrl;
        this.timeout = timeout;
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper();
        logger.info("OpaRestPolicyEvaluator initialized with OPA URL: {} (with injected OpaHttpClient)", opaBaseUrl);
    }

    @Override
    public boolean evaluate(String policyId, Map<String, Object> inputData) {
        logger.debug("Evaluating policy via OPA REST API: {}", policyId);
        PolicyEvaluationResult result = evaluateWithDetails(policyId, inputData);
        
        if (!result.isSuccess()) {
            throw new PolicyEvaluationException(result.getErrorMessage(), null, policyId);
        }
        return result.isAllowed();
    }

    @Override
    public PolicyEvaluationResult evaluateWithDetails(String policyId, Map<String, Object> inputData) {
        logger.debug("Evaluating policy with details via OPA REST API: {}", policyId);
        
        try {
            Policy policy = policyRegistry.get(policyId);
            
            // Convert Policy to OpaPolicy
            OpaPolicy opaPolicy = convertToOpaPolicy(policy);
            
            // Register policy with OPA server if not already registered
            registerPolicyWithOpa(opaPolicy);

            OpaEvaluationResult opaResult = callOpaEvaluation(opaPolicy.getPackageName(), opaPolicy.getRuleName(), inputData);
            
            String reasoning = buildReasoning(opaResult, opaPolicy);
            
            return new PolicyEvaluationResult(
                    opaResult.isAllowed(),
                    reasoning,
                    null,
                    opaResult.getResult()
            );
            
        } catch (PolicyNotFoundException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to evaluate policy via OPA REST API: {}", policyId, e);
            throw new PolicyEvaluationException(
                    "Failed to evaluate policy via OPA: " + e.getMessage(),
                    e,
                    policyId
            );
        }
    }

    private void registerPolicyWithOpa(OpaPolicy opaPolicy)
            throws Exception {
        String path = "/v1/policies/" + opaPolicy.getPackageName();
        String url = opaBaseUrl + path;

        logger.debug("Registering policy with OPA: {}", url);

        // Convert shorthand syntax to explicit if syntax for better OPA compatibility
        String normalizedPolicy = normalizeRegoPolicy(opaPolicy.getRegoPolicy());
        logger.debug("Original policy: {}", opaPolicy.getRegoPolicy());
        logger.debug("Normalized policy: {}", normalizedPolicy);

        // Use raw Rego policy in request body (not wrapped in JSON object)
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "text/plain")
                .timeout(timeout)
                .PUT(HttpRequest.BodyPublishers.ofString(normalizedPolicy))
                .build();

        OpaHttpResponse<String> response = httpClient.send(request, OpaBodyHandler.of(HttpResponse.BodyHandlers.ofString()));

        if (response.statusCode() != 200 && response.statusCode() != 201) {
            logger.warn("Failed to register policy with OPA (status: {}): {}", response.statusCode(), response.body());
            // Don't throw exception here as the policy might already be registered
        } else {
            logger.debug("Successfully registered policy with OPA");
        }
    }

    private OpaEvaluationResult callOpaEvaluation(String packageName, String ruleName, Map<String, Object> inputData)
            throws Exception {
        
        String path = String.format("/v1/data/%s/%s", packageName, ruleName);
        String url = opaBaseUrl + path;
        
        logger.debug("Calling OPA evaluation endpoint: {}", url);
        
        Map<String, Object> requestBody = Map.of("input", inputData);
        String requestBodyJson = objectMapper.writeValueAsString(requestBody);
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString(requestBodyJson))
                .build();
        
        OpaHttpResponse<String> response = httpClient.send(request, OpaBodyHandler.of(HttpResponse.BodyHandlers.ofString()));
        
        if (response.statusCode() != 200) {
            throw new PolicyEvaluationException(
                    "OPA evaluation failed with status code: " + response.statusCode() + 
                    ", body: " + response.body(),
                    null,
                    null
            );
        }
        
        return parseOpaResponse(response.body());
    }

    private OpaEvaluationResult parseOpaResponse(String responseBody) throws IOException {
        logger.debug("OPA response: {}", responseBody);
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        
        if (response.containsKey("result")) {
            Object result = response.get("result");
            boolean allowed = result instanceof Boolean ? (Boolean) result : false;
            
            Map<String, Object> output = new HashMap<>();
            output.put("allowed", allowed);
            output.put("result", result);
            if (response.containsKey("decision_id")) {
                output.put("decision_id", response.get("decision_id"));
            }
            
            return new OpaEvaluationResult(allowed, output);
        }
        
        return new OpaEvaluationResult(false, Map.of());
    }

    private String extractPackageName(String regoPolicy) {
        if (regoPolicy != null && regoPolicy.contains("package ")) {
            int start = regoPolicy.indexOf("package ") + 8;
            int end = regoPolicy.indexOf("\n", start);
            if (end == -1) {
                end = regoPolicy.length();
            }
            return regoPolicy.substring(start, end).trim();
        }
        return "default";
    }

    /**
     * Converts a Policy to an OpaPolicy.
     * <p>
     * This method extracts the necessary information from the Policy model
     * and creates an OpaPolicy instance that can be used for OPA evaluation.
     * </p>
     *
     * @param policy the policy to convert
     * @return the converted OpaPolicy
     */
    private OpaPolicy convertToOpaPolicy(Policy policy) {
        String packageName = extractPackageName(policy.getRegoPolicy());
        
        return new OpaPolicy.Builder()
                .version("1.0")
                .packageName(packageName)
                .ruleName("allow")
                .regoPolicy(policy.getRegoPolicy())
                .description(policy.getDescription())
                .build();
    }

    private String buildReasoning(OpaEvaluationResult result, OpaPolicy opaPolicy) {
        StringBuilder reasoning = new StringBuilder();
        
        reasoning.append("OPA evaluation result: ");
        reasoning.append(result.isAllowed() ? "ALLOWED" : "DENIED");
        reasoning.append(". ");
        
        if (opaPolicy.getDescription() != null) {
            reasoning.append(" Description: ");
            reasoning.append(opaPolicy.getDescription());
        }
        
        return reasoning.toString();
    }

    /**
     * Normalizes Rego policy by converting shorthand syntax to explicit if syntax.
     * This ensures compatibility with different OPA versions.
     * <p>
     * Example transformation:
     * <pre>
     * allow { input.amount <= 50 }
     * </pre>
     * becomes:
     * <pre>
     * allow if {
     *   input.amount <= 50
     * }
     * </pre>
     * </p>
     *
     * @param regoPolicy the original Rego policy
     * @return the normalized Rego policy
     */
    private String normalizeRegoPolicy(String regoPolicy) {
        // Pattern to match rule shorthand syntax: ruleName { body }
        // This converts it to: ruleName if { body }
        // We use a negative lookbehind to avoid matching "package" keyword
        return regoPolicy.replaceAll("(?<!package\\s)(\\w+)\\s*\\{\\s*", "$1 if { ");
    }

    private static class OpaEvaluationResult {
        private final boolean allowed;
        private final Map<String, Object> result;

        public OpaEvaluationResult(boolean allowed, Map<String, Object> result) {
            this.allowed = allowed;
            this.result = result;
        }

        public boolean isAllowed() {
            return allowed;
        }

        public Map<String, Object> getResult() {
            return result;
        }
    }
}