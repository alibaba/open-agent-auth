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
package com.alibaba.openagentauth.spring.web.provider;

import com.alibaba.openagentauth.core.model.context.OperationRequestContext;
import com.alibaba.openagentauth.core.model.evidence.Evidence;
import com.alibaba.openagentauth.core.model.evidence.VerifiableCredential;
import com.alibaba.openagentauth.core.model.oauth2.par.ParJwtClaims;
import com.alibaba.openagentauth.core.model.proposal.AgentUserBindingProposal;
import com.alibaba.openagentauth.core.protocol.vc.jwe.PromptDecryptionService;
import com.alibaba.openagentauth.core.protocol.vc.jwt.JwtVcDecoder;
import com.alibaba.openagentauth.framework.web.provider.ConsentPageProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.ModelAndView;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Default implementation of {@link ConsentPageProvider}.
 * <p>
 * This implementation provides a simple consent page template that displays
 * the authorization request details and allows users to approve or deny.
 * It uses a default Thymeleaf template located at {@code consent}.
 * </p>
 * <p>
 * <b>Template Model:</b></p>
 * <ul>
 *   <li>{@code requestUri} - The PAR request URI</li>
 *   <li>{@code subject} - The authenticated user subject</li>
 *   <li>{@code clientId} - The OAuth 2.0 client identifier</li>
 *   <li>{@code scopes} - The requested scopes</li>
 *   <li>{@code parClaims} - The PAR JWT claims (for Agent Operation Authorization)</li>
 *   <li>{@code evidence} - The user's original input as JWT-VC</li>
 *   <li>{@code operationProposal} - The Rego policy string</li>
 *   <li>{@code context} - The operation request context</li>
 * </ul>
 * <p>
 * <b>Form Submission:</b></p>
 * The consent page should submit a form with:
 * <ul>
 *   <li>{@code request_uri} - The PAR request URI</li>
 *   <li>{@code action} - Either "approve" or "deny"</li>
 * </ul>
 *
 * @see ConsentPageProvider
 * @since 1.0
 */
public class DefaultConsentPageProvider implements ConsentPageProvider {

    /**
     * The logger for consent page provider.
     */
    private static final Logger logger = LoggerFactory.getLogger(DefaultConsentPageProvider.class);

    /**
     * Default view name for the consent page.
     */
    public static final String DEFAULT_VIEW_NAME = "consent";

    /**
     * The Thymeleaf template view name.
     */
    private final String viewName;

    /**
     * The display name for the IDP (e.g., "AS User IDP", "Agent User IDP").
     */
    private final String displayName;

    /**
     * Service for decrypting JWE-encrypted user prompts.
     * <p>
     * When the source prompt credential is JWE-encrypted, this service decrypts it
     * so the consent page can display the human-readable original user input.
     * </p>
     */
    private final PromptDecryptionService promptDecryptionService;

    /**
     * Creates a new DefaultConsentPageProvider with default view name.
     */
    public DefaultConsentPageProvider() {
        this(DEFAULT_VIEW_NAME, "Identity Provider", null);
    }

    /**
     * Creates a new DefaultConsentPageProvider with custom view name.
     *
     * @param viewName the Thymeleaf template view name
     */
    public DefaultConsentPageProvider(String viewName) {
        this(viewName, "Identity Provider", null);
    }

    /**
     * Creates a new DefaultConsentPageProvider with custom view name and display name.
     *
     * @param viewName the Thymeleaf template view name
     * @param displayName the display name for the IDP
     */
    public DefaultConsentPageProvider(String viewName, String displayName) {
        this(viewName, displayName, null);
    }

    /**
     * Creates a new DefaultConsentPageProvider with custom view name, display name,
     * and prompt decryption service.
     *
     * @param viewName the Thymeleaf template view name
     * @param displayName the display name for the IDP
     * @param promptDecryptionService the service for decrypting JWE-encrypted prompts (nullable)
     */
    public DefaultConsentPageProvider(String viewName, String displayName,
                                      PromptDecryptionService promptDecryptionService) {
        this.viewName = viewName;
        this.displayName = displayName;
        this.promptDecryptionService = promptDecryptionService;
    }

    @Override
    public ModelAndView renderConsentPage(
            HttpServletRequest request,
            String requestUri,
            String subject,
            String clientId,
            String scopes
    ) {
        logger.info("Rendering consent page for user: {}, client: {}", subject, clientId);

        ModelAndView mv = new ModelAndView(viewName);
        mv.addObject("requestUri", requestUri);
        mv.addObject("subject", subject);
        mv.addObject("clientId", clientId);
        mv.addObject("scopes", scopes);
        mv.addObject("displayName", displayName);

        return mv;
    }

    @Override
    public ModelAndView renderConsentPage(
            HttpServletRequest request,
            String requestUri,
            String subject,
            String clientId,
            String scopes,
            ParJwtClaims parClaims
    ) {
        logger.info("Rendering consent page with PAR claims for user: {}, client: {}", subject, clientId);

        ModelAndView mv = new ModelAndView(viewName);
        mv.addObject("requestUri", requestUri);
        mv.addObject("subject", subject);
        mv.addObject("clientId", clientId);
        mv.addObject("scopes", scopes);
        mv.addObject("displayName", displayName);

        // Add Agent Operation Authorization specific information
        if (parClaims != null) {
            mv.addObject("parClaims", parClaims);
            
            // Extract individual components for easier template access
            Evidence evidence = parClaims.getEvidence();
            if (evidence != null) {
                mv.addObject("evidence", evidence);
                mv.addObject("sourcePromptCredential", evidence.getSourcePromptCredential());
                
                // Decode JWT-VC to extract human-readable original user input
                decodeAndAddUserInput(mv, evidence.getSourcePromptCredential());
            }

            String operationProposal = parClaims.getOperationProposal();
            if (operationProposal != null) {
                mv.addObject("operationProposal", operationProposal);
            }

            OperationRequestContext context = parClaims.getContext();
            if (context != null) {
                mv.addObject("context", context);
            }

            AgentUserBindingProposal bindingProposal = parClaims.getAgentUserBindingProposal();
            if (bindingProposal != null) {
                mv.addObject("agentUserBindingProposal", bindingProposal);
            }

            logger.info("Added PAR claims to model: evidence={}, operationProposal={}, context={}", 
                    evidence != null, operationProposal != null, context != null);
        }

        return mv;
    }

    @Override
    public boolean handleConsentResponse(HttpServletRequest request) {
        String action = request.getParameter("action");
        boolean approved = "approve".equalsIgnoreCase(action);

        logger.info("User consent action: {}, approved: {}", action, approved);
        return approved;
    }

    /**
     * Decodes the JWT-VC source prompt credential and adds human-readable user input to the model.
     * <p>
     * According to draft-liu-agent-operation-authorization-01 Section 3, the evidence field
     * contains a JWT-VC with the user's original natural-language instruction. The prompt
     * inside the JWT-VC's {@code credentialSubject} may itself be JWE-encrypted for privacy
     * protection. This method handles two layers of protection:
     * </p>
     * <ol>
     *   <li><b>Outer layer:</b> The entire {@code sourcePromptCredential} may be JWE-wrapped.
     *       If so, it is decrypted first to obtain the signed JWT-VC.</li>
     *   <li><b>Inner layer:</b> The {@code prompt} field inside the JWT-VC's credential subject
     *       may be JWE-encrypted. After JWT-VC decoding, the prompt is decrypted to obtain
     *       the human-readable text.</li>
     * </ol>
     *
     * @param modelAndView the ModelAndView to add decoded information to
     * @param sourcePromptCredential the JWT-VC string (possibly JWE-encrypted)
     */
    private void decodeAndAddUserInput(ModelAndView modelAndView, String sourcePromptCredential) {
        if (sourcePromptCredential == null || sourcePromptCredential.isEmpty()) {
            return;
        }

        try {
            // The sourcePromptCredential may be either a JWE-encrypted JWT-VC or a plain JWT-VC.
            // Attempt outer-level decryption first (handles JWE-wrapped JWT-VC).
            String jwtVcString = tryDecryptOrPassthrough(sourcePromptCredential);

            // If the string is still in JWE format (5 dot-separated segments) after
            // decryption attempt, it cannot be parsed as a signed JWT — skip decoding.
            if (isJweFormat(jwtVcString)) {
                logger.warn("Source prompt credential is JWE-encrypted and could not be decrypted. "
                        + "The raw credential will be shown on the consent page.");
                return;
            }

            VerifiableCredential verifiableCredential = JwtVcDecoder.decode(jwtVcString);
            populateModelFromCredential(modelAndView, verifiableCredential);
            logger.debug("Successfully decoded JWT-VC for consent page display");
        } catch (Exception e) {
            logger.warn("Failed to decode source prompt credential for consent page display. "
                    + "The raw JWT-VC will still be shown. Error: {}", e.getMessage());
        }
    }

    /**
     * Checks whether the given string is in JWE compact serialization format.
     * <p>
     * JWE compact serialization consists of 5 Base64url-encoded parts separated by dots:
     * {@code header.encryptedKey.iv.ciphertext.tag}
     * </p>
     *
     * @param token the token string to check
     * @return true if the string has exactly 5 dot-separated segments (JWE format)
     */
    private boolean isJweFormat(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        long dotCount = token.chars().filter(ch -> ch == '.').count();
        return dotCount == 4;
    }

    /**
     * Attempts to decrypt the credential string. If decryption fails (e.g., missing JWK),
     * returns the original string unchanged so that direct JWT parsing can be attempted.
     *
     * @param sourcePromptCredential the credential string (JWE or plain JWT)
     * @return the decrypted JWT string, or the original string if decryption is unavailable or fails
     */
    private String tryDecryptOrPassthrough(String sourcePromptCredential) {
        if (promptDecryptionService == null) {
            return sourcePromptCredential;
        }
        try {
            return promptDecryptionService.decryptPrompt(sourcePromptCredential);
        } catch (Exception decryptionError) {
            logger.debug("JWE decryption failed ({}), attempting direct JWT parsing",
                    decryptionError.getMessage());
            return sourcePromptCredential;
        }
    }

    /**
     * Populates the ModelAndView with human-readable fields extracted from the decoded credential.
     *
     * @param modelAndView the ModelAndView to populate
     * @param credential the decoded VerifiableCredential
     */
    private void populateModelFromCredential(ModelAndView modelAndView, VerifiableCredential credential) {
        modelAndView.addObject("decodedCredential", credential);

        if (credential.getCredentialSubject() == null) {
            return;
        }

        String originalPrompt = credential.getCredentialSubject().getPrompt();
        if (originalPrompt != null && !originalPrompt.isEmpty()) {
            // The prompt field inside the JWT-VC may itself be JWE-encrypted.
            // Attempt decryption so the consent page shows the human-readable text.
            String decryptedPrompt = tryDecryptOrPassthrough(originalPrompt);
            if (isJweFormat(decryptedPrompt)) {
                logger.warn("Prompt inside JWT-VC credential is JWE-encrypted and could not be decrypted.");
            } else {
                modelAndView.addObject("originalUserPrompt", decryptedPrompt);
            }
        }

        String inputChannel = credential.getCredentialSubject().getChannel();
        if (inputChannel != null && !inputChannel.isEmpty()) {
            modelAndView.addObject("inputChannel", inputChannel);
        }

        String inputTimestamp = credential.getCredentialSubject().getTimestamp();
        if (inputTimestamp != null && !inputTimestamp.isEmpty()) {
            modelAndView.addObject("inputTimestamp", formatTimestamp(inputTimestamp));
        }
    }

    /**
     * Formats an ISO 8601 UTC timestamp into a human-readable local date-time string.
     * <p>
     * Converts timestamps like {@code 2025-11-11T10:30:00Z} into {@code 2025-11-11 10:30:00 UTC}.
     * If parsing fails, returns the original string unchanged.
     * </p>
     *
     * @param isoTimestamp the ISO 8601 timestamp string
     * @return the formatted timestamp, or the original string if parsing fails
     */
    private String formatTimestamp(String isoTimestamp) {
        try {
            Instant instant = Instant.parse(isoTimestamp);
            ZonedDateTime zonedDateTime = instant.atZone(ZoneOffset.UTC);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM d, yyyy, h:mm a 'UTC'", Locale.ENGLISH);
            return zonedDateTime.format(formatter);
        } catch (Exception e) {
            logger.debug("Failed to parse timestamp '{}', using original value", isoTimestamp);
            return isoTimestamp;
        }
    }

    @Override
    public boolean isConsentRequired(
            HttpServletRequest request,
            String subject,
            String clientId,
            String scopes
    ) {
        // Default implementation always requires consent
        // Implementations can override to skip consent for previously approved requests
        return true;
    }

    @Override
    public ModelAndView renderConsentPageTraditional(
            HttpServletRequest request,
            String subject,
            String clientId,
            String redirectUri,
            String state,
            String scopes
    ) {
        logger.info("Rendering traditional consent page for user: {}, client: {}", subject, clientId);

        ModelAndView mv = new ModelAndView(viewName);
        mv.addObject("requestUri", null); // Traditional flow doesn't use request_uri
        mv.addObject("subject", subject);
        mv.addObject("clientId", clientId);
        mv.addObject("redirectUri", redirectUri);
        mv.addObject("state", state);
        mv.addObject("scopes", scopes);
        mv.addObject("displayName", displayName);

        return mv;
    }
}