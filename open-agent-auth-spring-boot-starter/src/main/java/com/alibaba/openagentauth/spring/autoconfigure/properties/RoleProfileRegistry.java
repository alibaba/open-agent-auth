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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.*;

/**
 * Registry of built-in role profiles.
 * <p>
 * This registry defines the default configuration profile for each role in the
 * Open Agent Auth framework. When a role is enabled, the framework uses the
 * corresponding profile to automatically infer required keys, peers, and capabilities.
 * </p>
 * <p>
 * The profiles encode the domain knowledge about each role's requirements:
 * <ul>
 *   <li><b>Agent IDP</b>: Signs WITs, verifies ID Tokens from Agent User IDP</li>
 *   <li><b>Agent</b>: Signs PAR-JWTs and VCs, verifies WITs, encrypts prompts</li>
 *   <li><b>Authorization Server</b>: Signs AOATs, decrypts JWE, verifies WITs</li>
 *   <li><b>Resource Server</b>: Verifies WITs and AOATs</li>
 *   <li><b>Agent User IDP</b>: Signs ID Tokens</li>
 *   <li><b>AS User IDP</b>: Signs ID Tokens</li>
 * </ul>
 *
 * @since 2.1
 */
public final class RoleProfileRegistry {

    private static final Map<String, RoleProfile> PROFILES;

    static {
        Map<String, RoleProfile> profiles = new LinkedHashMap<>();

        profiles.put(ROLE_AGENT_IDP, RoleProfile.builder()
                .signingKeys(KEY_WIT_SIGNING)
                .verificationKeys(KEY_ID_TOKEN_VERIFICATION)
                .requiredPeers(SERVICE_AGENT_USER_IDP)
                .requiredCapabilities("workload-identity")
                .jwksProviderEnabled(true)
                .keyDefaultAlgorithms(Map.of(
                        KEY_WIT_SIGNING, "ES256",
                        KEY_ID_TOKEN_VERIFICATION, "ES256"
                ))
                .keyToPeerMapping(Map.of(
                        KEY_ID_TOKEN_VERIFICATION, SERVICE_AGENT_USER_IDP
                ))
                .build());

        profiles.put(ROLE_AGENT, RoleProfile.builder()
                .signingKeys(KEY_PAR_JWT_SIGNING, KEY_VC_SIGNING)
                .verificationKeys(KEY_WIT_VERIFICATION, KEY_ID_TOKEN_VERIFICATION)
                .encryptionKeys(KEY_JWE_ENCRYPTION)
                .requiredPeers(SERVICE_AGENT_IDP, SERVICE_AGENT_USER_IDP, SERVICE_AUTHORIZATION_SERVER)
                .requiredCapabilities("oauth2-client", "operation-authorization",
                        "operation-authorization.prompt-encryption")
                .jwksProviderEnabled(true)
                .keyDefaultAlgorithms(Map.of(
                        KEY_PAR_JWT_SIGNING, "RS256",
                        KEY_VC_SIGNING, "ES256",
                        KEY_WIT_VERIFICATION, "ES256",
                        KEY_ID_TOKEN_VERIFICATION, "ES256",
                        KEY_JWE_ENCRYPTION, "RS256"
                ))
                .keyToPeerMapping(Map.of(
                        KEY_WIT_VERIFICATION, SERVICE_AGENT_IDP,
                        KEY_ID_TOKEN_VERIFICATION, SERVICE_AGENT_USER_IDP,
                        KEY_JWE_ENCRYPTION, SERVICE_AUTHORIZATION_SERVER
                ))
                .build());

        profiles.put(ROLE_AUTHORIZATION_SERVER, RoleProfile.builder()
                .signingKeys(KEY_AOAT_SIGNING)
                .verificationKeys(KEY_WIT_VERIFICATION)
                .decryptionKeys(KEY_JWE_DECRYPTION)
                .requiredPeers(SERVICE_AS_USER_IDP, SERVICE_AGENT)
                .requiredCapabilities("oauth2-server", "operation-authorization",
                        "operation-authorization.prompt-encryption")
                .jwksProviderEnabled(true)
                .keyDefaultAlgorithms(Map.of(
                        KEY_AOAT_SIGNING, "RS256",
                        KEY_JWE_DECRYPTION, "RS256",
                        KEY_WIT_VERIFICATION, "ES256"
                ))
                .keyToPeerMapping(Map.of(
                        KEY_WIT_VERIFICATION, SERVICE_AGENT_IDP
                ))
                .build());

        profiles.put(ROLE_RESOURCE_SERVER, RoleProfile.builder()
                .verificationKeys(KEY_WIT_VERIFICATION, KEY_AOAT_VERIFICATION)
                .requiredPeers(SERVICE_AGENT_IDP, SERVICE_AUTHORIZATION_SERVER)
                .requiredCapabilities()
                .jwksProviderEnabled(true)
                .keyDefaultAlgorithms(Map.of(
                        KEY_WIT_VERIFICATION, "ES256",
                        KEY_AOAT_VERIFICATION, "RS256"
                ))
                .keyToPeerMapping(Map.of(
                        KEY_WIT_VERIFICATION, SERVICE_AGENT_IDP,
                        KEY_AOAT_VERIFICATION, SERVICE_AUTHORIZATION_SERVER
                ))
                .build());

        profiles.put(ROLE_AGENT_USER_IDP, RoleProfile.builder()
                .signingKeys(KEY_ID_TOKEN_SIGNING)
                .jwksProviderEnabled(true)
                .keyDefaultAlgorithms(Map.of(
                        KEY_ID_TOKEN_SIGNING, "ES256"
                ))
                .build());

        profiles.put(ROLE_AS_USER_IDP, RoleProfile.builder()
                .signingKeys(KEY_ID_TOKEN_SIGNING)
                .jwksProviderEnabled(true)
                .keyDefaultAlgorithms(Map.of(
                        KEY_ID_TOKEN_SIGNING, "ES256"
                ))
                .build());

        PROFILES = Collections.unmodifiableMap(profiles);
    }

    private RoleProfileRegistry() {
        throw new AssertionError("No instances");
    }

    /**
     * Gets the role profile for the given role name.
     *
     * @param roleName the role name (e.g., "agent-idp")
     * @return the role profile, or null if no profile is defined for the role
     */
    public static RoleProfile getProfile(String roleName) {
        return PROFILES.get(roleName);
    }

    /**
     * Gets all registered role profiles.
     *
     * @return unmodifiable map of role name to role profile
     */
    public static Map<String, RoleProfile> getAllProfiles() {
        return PROFILES;
    }
}
