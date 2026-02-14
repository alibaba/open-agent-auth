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
package com.alibaba.openagentauth.framework.orchestration;

import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.model.token.AgentOperationAuthToken;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitParser;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptParser;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.token.aoat.AoatParser;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.validation.api.FiveLayerVerifier;
import com.alibaba.openagentauth.core.validation.impl.FiveLayerVerifierFactory;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;
import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.VerificationResult;
import com.alibaba.openagentauth.framework.actor.ResourceServer;
import com.alibaba.openagentauth.framework.exception.validation.FrameworkValidationException;
import com.alibaba.openagentauth.framework.model.audit.AuditLogEntry;
import com.alibaba.openagentauth.framework.model.request.ResourceRequest;
import com.alibaba.openagentauth.framework.model.validation.ValidationResult;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;


/**
 * Default orchestration implementation for Resource Server.
 * <p>
 * This orchestrator implements the five-layer verification architecture for resource access,
 * providing comprehensive security validation and policy enforcement.
 * </p>
 *
 * <h3>Core Responsibilities:</h3>
 * <ul>
 *   <li><b>Layer 1: Workload Authentication:</b> Validates WIT signature and claims</li>
 *   <li><b>Layer 2: Request Integrity:</b> Validates WPT signature and integrity</li>
 *   <li><b>Layer 3: User Authentication:</b> Validates AOAT signature and claims</li>
 *   <li><b>Layer 4: Identity Consistency:</b> Verifies user-workload identity binding</li>
 *   <li><b>Layer 5: Policy Evaluation:</b> Evaluates OPA policies for authorization</li>
 *   <li><b>Audit Logging:</b> Records all access attempts and decisions</li>
 * </ul>
 *
 * @see ResourceServer
 * @since 1.0
 */
public class DefaultResourceServer implements ResourceServer {

    // Logger
    private static final Logger logger = LoggerFactory.getLogger(DefaultResourceServer.class);

    private final WitParser witParser;
    private final AoatParser aoatParser;
    private final WptParser wptParser;
    private final FiveLayerVerifier fiveLayerVerifier;

    /**
     * Creates a new ResourceServerOrchestrator.
     *
     * @param witValidator the WIT validator
     * @param wptValidator the WPT validator
     * @param aoatValidator the AOAT validator
     * @param policyEvaluator the policy evaluator
     * @param bindingInstanceStore the binding instance store for two-layer verification (optional)
     */
    public DefaultResourceServer(WitValidator witValidator,
                                 WptValidator wptValidator,
                                 AoatValidator aoatValidator,
                                 PolicyEvaluator policyEvaluator,
                                 BindingInstanceStore bindingInstanceStore) {

        // Validate parameters
        this.witParser = new WitParser();
        this.aoatParser = new AoatParser();
        this.wptParser = new WptParser();
        
        // Create the five-layer verifier using factory
        this.fiveLayerVerifier = FiveLayerVerifierFactory.createVerifier(
            ValidationUtils.validateNotNull(witValidator, "WIT validator"),
            ValidationUtils.validateNotNull(wptValidator, "WPT validator"),
            ValidationUtils.validateNotNull(aoatValidator, "AOAT validator"),
            policyEvaluator,
            bindingInstanceStore
        );
        
        logger.info("ResourceServerOrchestrator initialized");
    }

    /**
     * Validates a resource request.
     *
     * @param request the resource request
     * @return a ValidationResult containing the validation outcome and parsed tokens
     * @throws FrameworkValidationException if validation fails
     */
    @Override
    public ValidationResult validateRequest(ResourceRequest request) throws FrameworkValidationException {

        // Validate request
        ValidationUtils.validateNotNull(request, "Resource request");

        logger.debug("Validating request with five-layer verification");

        try {
            // Parse tokens from request
            WorkloadIdentityToken wit = parseWit(request.getWit());
            WorkloadProofToken wpt = parseWpt(request.getWpt());
            AgentOperationAuthToken aoat = parseAoat(request.getAoat());

            // Build validation context
            ValidationContext context = ValidationContext.builder()
                    .wit(wit)
                    .wpt(wpt)
                    .agentOaToken(aoat)
                    .httpMethod(request.getHttpMethod())
                    .httpUri(request.getHttpUri())
                    .httpHeaders(request.getHttpHeaders())
                    .httpBody(request.getHttpBody())
                    .addAttribute("operationType", request.getOperationType())
                    .addAttribute("resourceId", request.getResourceId())
                    .addAttribute("context", request.getParameters())
                    .build();

            // Execute five-layer verification
            VerificationResult verificationResult = fiveLayerVerifier.verify(context);

            // Convert verification result to framework ValidationResult
            return convertToValidationResult(verificationResult);

        } catch (Exception e) {
            logger.error("Request validation failed", e);
            throw new FrameworkValidationException("Request validation failed: " + e.getMessage(), e);
        }
    }

    @Override
    public void logAccess(AuditLogEntry auditLog) {
        ValidationUtils.validateNotNull(auditLog, "Audit log");

        logger.info("Access logged: userId={}, workloadId={}, resourceId={}, decision={}",
                auditLog.getUserId(),
                auditLog.getWorkloadId(),
                auditLog.getResourceId(),
                auditLog.getDecision());
    }

    /**
     * Parses WIT string to WorkloadIdentityToken object.
     *
     * @param witString the WIT JWT string
     * @return the parsed WorkloadIdentityToken
     * @throws FrameworkValidationException if parsing fails
     */
    private WorkloadIdentityToken parseWit(String witString) throws FrameworkValidationException {
        
        if (ValidationUtils.isNullOrEmpty(witString)) {
            throw new FrameworkValidationException("WIT is required");
        }
        
        try {
            SignedJWT signedJwt = SignedJWT.parse(witString);
            return witParser.parse(signedJwt);
        } catch (ParseException e) {
            throw new FrameworkValidationException("Failed to parse WIT: " + e.getMessage(), e);
        }
    }

    /**
     * Parses WPT string to WorkloadProofToken object.
     *
     * @param wptString the WPT JWT string
     * @return the parsed WorkloadProofToken
     * @throws FrameworkValidationException if parsing fails
     */
    private WorkloadProofToken parseWpt(String wptString) throws FrameworkValidationException {
        
        if (ValidationUtils.isNullOrEmpty(wptString)) {
            throw new FrameworkValidationException("WPT is required");
        }
        
        try {
            return wptParser.parse(wptString);
        } catch (Exception e) {
            throw new FrameworkValidationException("Failed to parse WPT: " + e.getMessage(), e);
        }
    }

    /**
     * Parses AOAT string to AgentOperationAuthToken object.
     *
     * @param aoatString the AOAT JWT string
     * @return the parsed AgentOperationAuthToken
     * @throws FrameworkValidationException if parsing fails
     */
    private AgentOperationAuthToken parseAoat(String aoatString) throws FrameworkValidationException {
        
        if (ValidationUtils.isNullOrEmpty(aoatString)) {
            throw new FrameworkValidationException("AOAT is required");
        }
        
        try {
            SignedJWT signedJwt = SignedJWT.parse(aoatString);
            return aoatParser.parse(signedJwt);
        } catch (ParseException e) {
            throw new FrameworkValidationException("Failed to parse AOAT: " + e.getMessage(), e);
        }
    }

    /**
     * Converts VerificationResult to framework ValidationResult.
     *
     * @param verificationResult the verification result from core package
     * @return the framework validation result
     */
    private ValidationResult convertToValidationResult(VerificationResult verificationResult) {
        
        // Convert layer results
        List<ValidationResult.LayerResult> layerResults = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        
        // Convert errors
        for (VerificationResult.LayerResult layerResult : verificationResult.getLayerResults()) {

            // Convert layer result
            LayerValidationResult coreResult = layerResult.getResult();
            ValidationResult.LayerResult frameworkLayerResult = ValidationResult.LayerResult.builder()
                    .layer((int) layerResult.getOrder())
                    .layerName(layerResult.getValidatorName())
                    .valid(coreResult.isSuccess())
                    .message(coreResult.isSuccess() ? "Validation passed" : String.join(", ", coreResult.getErrors()))
                    .build();

            // Add to layer results
            layerResults.add(frameworkLayerResult);
            if (!coreResult.isSuccess()) {
                errors.addAll(coreResult.getErrors());
            }
        }
        
        return ValidationResult.builder()
                .valid(verificationResult.isSuccess())
                .layerResults(layerResults)
                .errors(errors)
                .build();
    }

}