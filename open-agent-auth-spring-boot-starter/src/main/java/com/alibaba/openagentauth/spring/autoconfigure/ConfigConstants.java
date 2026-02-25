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
package com.alibaba.openagentauth.spring.autoconfigure;

/**
 * Centralized constants for auto-configuration classes.
 * <p>
 * This class eliminates hardcoded "magic strings" scattered across AutoConfiguration classes
 * by providing a single source of truth for role names, service discovery identifiers,
 * key management identifiers, JWKS consumer names, and template paths.
 * </p>
 * <p>
 * These constants correspond to the keys used in {@code application.yml} configuration,
 * for example:
 * </p>
 * <pre>
 * open-agent-auth:
 *   roles:
 *     agent:          # matches {@link #ROLE_AGENT}
 *       enabled: true
 *   infrastructures:
 *     service-discovery:
 *       services:
 *         agent-idp:  # matches {@link #SERVICE_AGENT_IDP}
 *           base-url: http://localhost:8082
 *     key-management:
 *       keys:
 *         wit-verification:  # matches {@link #KEY_WIT_VERIFICATION}
 *           key-id: wit-signing-key
 * </pre>
 *
 * @since 1.0
 */
public final class ConfigConstants {

    private ConfigConstants() {
        throw new AssertionError("No instances");
    }

    // ==================== Role Names ====================
    // Used in: openAgentAuthProperties.getRoles().get(ROLE_*)

    /** Role name for the Agent. */
    public static final String ROLE_AGENT = "agent";

    /** Role name for the Authorization Server. */
    public static final String ROLE_AUTHORIZATION_SERVER = "authorization-server";

    /** Role name for the Agent User Identity Provider. */
    public static final String ROLE_AGENT_USER_IDP = "agent-user-idp";

    /** Role name for the Agent Identity Provider. */
    public static final String ROLE_AGENT_IDP = "agent-idp";

    /** Role name for the Authorization Server User Identity Provider. */
    public static final String ROLE_AS_USER_IDP = "as-user-idp";

    /** Role name for the Resource Server. */
    public static final String ROLE_RESOURCE_SERVER = "resource-server";

    // ==================== Service Discovery Names ====================
    // Used in: getServiceDiscovery().getServices().get(SERVICE_*)
    // Also used as JWKS consumer names: getJwks().getConsumers().get(SERVICE_*)

    /** Service discovery name for the Agent IDP. */
    public static final String SERVICE_AGENT_IDP = "agent-idp";

    /** Service discovery name for the Agent User IDP. */
    public static final String SERVICE_AGENT_USER_IDP = "agent-user-idp";

    /** Service discovery name for the Authorization Server. */
    public static final String SERVICE_AUTHORIZATION_SERVER = "authorization-server";

    /** Service discovery name for the Resource Server. */
    public static final String SERVICE_RESOURCE_SERVER = "resource-server";

    /** Service discovery name for the AS User IDP. */
    public static final String SERVICE_AS_USER_IDP = "as-user-idp";

    /** Service discovery name for the Agent. */
    public static final String SERVICE_AGENT = "agent";

    // ==================== Key Management Names ====================
    // Used in: getKeyManagement().getKeys().get(KEY_*)

    /** Key name for WIT signing (EC private key for Agent IDP). */
    public static final String KEY_WIT_SIGNING = "wit-signing";

    /** Key name for WIT verification (EC public key from Agent IDP). */
    public static final String KEY_WIT_VERIFICATION = "wit-verification";

    /** Key name for PAR-JWT signing (RSA private key for Agent). */
    public static final String KEY_PAR_JWT_SIGNING = "par-jwt-signing";

    /** Key name for Verifiable Credential signing (EC private key for Agent). */
    public static final String KEY_VC_SIGNING = "vc-signing";

    /** Key name for JWE encryption (RSA public key from Authorization Server). */
    public static final String KEY_JWE_ENCRYPTION = "jwe-encryption";

    /** Key name for JWE decryption (RSA private key for Authorization Server). */
    public static final String KEY_JWE_DECRYPTION = "jwe-decryption";

    /** Key name for AOAT signing (RSA private key for Authorization Server). */
    public static final String KEY_AOAT_SIGNING = "aoat-signing";

    /** Key name for AOAT verification (RSA public key from Authorization Server). */
    public static final String KEY_AOAT_VERIFICATION = "aoat-verification";

    /** Key name for ID Token signing (EC private key for User IDPs). */
    public static final String KEY_ID_TOKEN_SIGNING = "id-token-signing";

    /** Key name for ID Token verification (EC public key from User IDPs, fetched via JWKS). */
    public static final String KEY_ID_TOKEN_VERIFICATION = "id-token-verification";

    // ==================== Well-Known Paths ====================

    /** Standard OIDC JWKS endpoint path. */
    public static final String JWKS_WELL_KNOWN_PATH = "/.well-known/jwks.json";

    /** OAA (Open Agent Auth) configuration metadata endpoint path. */
    public static final String OAA_CONFIGURATION_PATH = "/.well-known/oaa-configuration";

    // ==================== Consent Page Templates ====================

    /** Thymeleaf template path for OIDC consent page. */
    public static final String CONSENT_TEMPLATE_OIDC = "oauth2/oidc_consent";

    /** Thymeleaf template path for AOA (Agent Operation Authorization) consent page. */
    public static final String CONSENT_TEMPLATE_AOA = "oauth2/aoa_consent";

    // ==================== Default Callback Endpoint ====================

    /** Default OAuth2 callback endpoint path. */
    public static final String DEFAULT_CALLBACK_ENDPOINT = "/callback";
}
