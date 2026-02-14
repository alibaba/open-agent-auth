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
package com.alibaba.openagentauth.core.validation.impl;

import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.policy.api.PolicyEvaluator;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.validation.api.FiveLayerVerifier;
import com.alibaba.openagentauth.core.validation.layer.OperationAuthorizationValidator;
import com.alibaba.openagentauth.core.validation.layer.IdentityConsistencyValidator;
import com.alibaba.openagentauth.core.validation.layer.PolicyEvaluationValidator;
import com.alibaba.openagentauth.core.validation.layer.WorkloadIdentityValidator;
import com.alibaba.openagentauth.core.validation.layer.WorkloadProofValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory class for creating and configuring the five-layer verifier.
 * <p>
 * This factory encapsulates the initialization logic for all validators,
 * providing a clean separation of concerns. The ResourceServerProvider
 * only needs to call this factory to get a fully configured verifier.
 * </p>
 *
 * <h3>Validators Registered:</h3>
 * <ul>
 *   <li><b>Layer 1:</b> WorkloadIdentityValidator - Validates WIT signature and claims</li>
 *   <li><b>Layer 2:</b> WorkloadProofValidator - Validates WPT signature and integrity</li>
 *   <li><b>Layer 3:</b> AgentOperationAuthorizationValidator - Validates AOAT signature and claims</li>
 *   <li><b>Layer 4:</b> IdentityConsistencyValidator - Verifies user-workload identity binding</li>
 *   <li><b>Layer 5:</b> PolicyEvaluationValidator - Evaluates OPA policies for authorization</li>
 * </ul>
 *
 * @see FiveLayerVerifier
 * @see DefaultFiveLayerVerifier
 * @since 1.0
 */
public class FiveLayerVerifierFactory {

    /**
     * The logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(FiveLayerVerifierFactory.class);

    /**
     * Creates a fully configured five-layer verifier with all validators registered.
     * <p>
     * This method encapsulates the initialization of all validators in the correct order,
     * following the five-layer verification architecture:
     * <ol>
     *   <li>Workload Identity Validation</li>
     *   <li>Workload Proof Validation</li>
     *   <li>Agent Operation Authorization Validation</li>
     *   <li>Identity Consistency Validation</li>
     *   <li>Policy Evaluation Validation</li>
     * </ol>
     * </p>
     *
     * @param witValidator the WIT validator (required)
     * @param wptValidator the WPT validator (required)
     * @param aoatValidator the AOAT validator (required)
     * @param policyEvaluator the policy evaluator (required)
     * @param bindingInstanceStore the binding instance store for two-layer verification (optional)
     * @return a fully configured FiveLayerVerifier instance
     * @throws IllegalArgumentException if any required parameter is null
     */
    public static FiveLayerVerifier createVerifier(WitValidator witValidator,
                                                   WptValidator wptValidator,
                                                   AoatValidator aoatValidator,
                                                   PolicyEvaluator policyEvaluator,
                                                   BindingInstanceStore bindingInstanceStore) {
        
        validateParameters(witValidator, wptValidator, aoatValidator, policyEvaluator);

        logger.info("Creating five-layer verifier with all validators");

        DefaultFiveLayerVerifier verifier = new DefaultFiveLayerVerifier();

        registerValidators(verifier, witValidator, wptValidator, aoatValidator, policyEvaluator, bindingInstanceStore);

        logger.info("Five-layer verifier created successfully with 5 validators");

        return verifier;
    }

    /**
     * Validates the required parameters for creating a verifier.
     *
     * @param witValidator the WIT validator
     * @param wptValidator the WPT validator
     * @param aoatValidator the AOAT validator
     * @param policyEvaluator the policy evaluator
     * @throws IllegalArgumentException if any required parameter is null
     */
    private static void validateParameters(WitValidator witValidator,
                                          WptValidator wptValidator,
                                          AoatValidator aoatValidator,
                                          PolicyEvaluator policyEvaluator) {
        ValidationUtils.validateNotNull(witValidator, "WIT validator");
        ValidationUtils.validateNotNull(wptValidator, "WPT validator");
        ValidationUtils.validateNotNull(aoatValidator, "AOAT validator");
        ValidationUtils.validateNotNull(policyEvaluator, "Policy evaluator");
    }

    /**
     * Registers all validators to the verifier instance.
     *
     * @param verifier the verifier instance
     * @param witValidator the WIT validator
     * @param wptValidator the WPT validator
     * @param aoatValidator the AOAT validator
     * @param policyEvaluator the policy evaluator
     * @param bindingInstanceStore the binding instance store for two-layer verification
     */
    private static void registerValidators(DefaultFiveLayerVerifier verifier,
                                          WitValidator witValidator,
                                          WptValidator wptValidator,
                                          AoatValidator aoatValidator,
                                          PolicyEvaluator policyEvaluator,
                                          BindingInstanceStore bindingInstanceStore) {

        // Register Layer 1: Workload Identity Validator
        verifier.registerValidator(new WorkloadIdentityValidator(witValidator));
        logger.debug("Registered Layer 1 validator: WorkloadIdentityValidator");

        // Register Layer 2: Workload Proof Validator
        verifier.registerValidator(new WorkloadProofValidator(wptValidator));
        logger.debug("Registered Layer 2 validator: WorkloadProofValidator");

        // Register Layer 3: Agent Operation Authorization Validator
        verifier.registerValidator(new OperationAuthorizationValidator(aoatValidator));
        logger.debug("Registered Layer 3 validator: AgentOperationAuthorizationValidator");

        // Register Layer 4: Identity Consistency Validator with binding instance store
        verifier.registerValidator(new IdentityConsistencyValidator(bindingInstanceStore));
        logger.debug("Registered Layer 4 validator: IdentityConsistencyValidator");

        // Register Layer 5: Policy Evaluation Validator
        verifier.registerValidator(new PolicyEvaluationValidator(policyEvaluator));
        logger.debug("Registered Layer 5 validator: PolicyEvaluationValidator");

    }
}
