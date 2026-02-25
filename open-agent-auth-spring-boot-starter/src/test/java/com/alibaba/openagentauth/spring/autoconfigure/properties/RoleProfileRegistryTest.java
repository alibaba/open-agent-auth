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

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static com.alibaba.openagentauth.spring.autoconfigure.ConfigConstants.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link RoleProfileRegistry}.
 *
 * @since 2.1
 */
@SpringBootTest(classes = TestConfiguration.class)
class RoleProfileRegistryTest {

    @Test
    void testAllSixRolesExist() {
        assertNotNull(RoleProfileRegistry.getProfile(ROLE_AGENT_IDP));
        assertNotNull(RoleProfileRegistry.getProfile(ROLE_AGENT));
        assertNotNull(RoleProfileRegistry.getProfile(ROLE_AUTHORIZATION_SERVER));
        assertNotNull(RoleProfileRegistry.getProfile(ROLE_RESOURCE_SERVER));
        assertNotNull(RoleProfileRegistry.getProfile(ROLE_AGENT_USER_IDP));
        assertNotNull(RoleProfileRegistry.getProfile(ROLE_AS_USER_IDP));
    }

    @Test
    void testGetProfileReturnsNullForUnknownRole() {
        assertNull(RoleProfileRegistry.getProfile("unknown-role"));
        assertNull(RoleProfileRegistry.getProfile("non-existent"));
        assertNull(RoleProfileRegistry.getProfile(""));
    }

    @Test
    void testGetAllProfilesReturnsImmutableMap() {
        assertThrows(UnsupportedOperationException.class, () -> 
            RoleProfileRegistry.getAllProfiles().put("new-role", RoleProfile.builder().build())
        );
    }

    @Test
    void testGetAllProfilesSize() {
        assertEquals(6, RoleProfileRegistry.getAllProfiles().size());
    }

    @Test
    void testAgentIdpProfile() {
        RoleProfile profile = RoleProfileRegistry.getProfile(ROLE_AGENT_IDP);
        
        assertEquals(List.of(KEY_WIT_SIGNING), profile.getSigningKeys());
        assertEquals(List.of(KEY_ID_TOKEN_VERIFICATION), profile.getVerificationKeys());
        assertEquals(List.of(SERVICE_AGENT_USER_IDP), profile.getRequiredPeers());
        assertEquals(List.of("workload-identity"), profile.getRequiredCapabilities());
        assertEquals(true, profile.isJwksProviderEnabled());
        assertEquals("ES256", profile.getDefaultAlgorithm(KEY_WIT_SIGNING));
        assertEquals("ES256", profile.getDefaultAlgorithm(KEY_ID_TOKEN_VERIFICATION));
        assertEquals(SERVICE_AGENT_USER_IDP, profile.getPeerForKey(KEY_ID_TOKEN_VERIFICATION));
    }

    @Test
    void testAgentProfile() {
        RoleProfile profile = RoleProfileRegistry.getProfile(ROLE_AGENT);
        
        assertEquals(List.of(KEY_PAR_JWT_SIGNING, KEY_VC_SIGNING), profile.getSigningKeys());
        assertEquals(List.of(KEY_WIT_VERIFICATION, KEY_ID_TOKEN_VERIFICATION), profile.getVerificationKeys());
        assertEquals(List.of(KEY_JWE_ENCRYPTION), profile.getEncryptionKeys());
        assertEquals(List.of(SERVICE_AGENT_IDP, SERVICE_AGENT_USER_IDP, SERVICE_AUTHORIZATION_SERVER), profile.getRequiredPeers());
        assertEquals(List.of("oauth2-client", "operation-authorization", "operation-authorization.prompt-encryption"), profile.getRequiredCapabilities());
        assertEquals(true, profile.isJwksProviderEnabled());
        
        assertEquals("RS256", profile.getDefaultAlgorithm(KEY_PAR_JWT_SIGNING));
        assertEquals("ES256", profile.getDefaultAlgorithm(KEY_VC_SIGNING));
        assertEquals("ES256", profile.getDefaultAlgorithm(KEY_WIT_VERIFICATION));
        assertEquals("ES256", profile.getDefaultAlgorithm(KEY_ID_TOKEN_VERIFICATION));
        assertEquals("RS256", profile.getDefaultAlgorithm(KEY_JWE_ENCRYPTION));
        
        assertEquals(SERVICE_AGENT_IDP, profile.getPeerForKey(KEY_WIT_VERIFICATION));
        assertEquals(SERVICE_AGENT_USER_IDP, profile.getPeerForKey(KEY_ID_TOKEN_VERIFICATION));
        assertEquals(SERVICE_AUTHORIZATION_SERVER, profile.getPeerForKey(KEY_JWE_ENCRYPTION));
    }

    @Test
    void testAuthorizationServerProfile() {
        RoleProfile profile = RoleProfileRegistry.getProfile(ROLE_AUTHORIZATION_SERVER);
        
        assertEquals(List.of(KEY_AOAT_SIGNING), profile.getSigningKeys());
        assertEquals(List.of(KEY_WIT_VERIFICATION), profile.getVerificationKeys());
        assertEquals(List.of(KEY_JWE_DECRYPTION), profile.getDecryptionKeys());
        assertEquals(List.of(SERVICE_AS_USER_IDP, SERVICE_AGENT), profile.getRequiredPeers());
        assertEquals(List.of("oauth2-server", "operation-authorization", "operation-authorization.prompt-encryption"), profile.getRequiredCapabilities());
        assertEquals(true, profile.isJwksProviderEnabled());
        
        assertEquals("RS256", profile.getDefaultAlgorithm(KEY_AOAT_SIGNING));
        assertEquals("RS256", profile.getDefaultAlgorithm(KEY_JWE_DECRYPTION));
        assertEquals("ES256", profile.getDefaultAlgorithm(KEY_WIT_VERIFICATION));
        
        assertEquals(SERVICE_AGENT_IDP, profile.getPeerForKey(KEY_WIT_VERIFICATION));
    }

    @Test
    void testResourceServerProfile() {
        RoleProfile profile = RoleProfileRegistry.getProfile(ROLE_RESOURCE_SERVER);
        
        assertEquals(List.of(KEY_WIT_VERIFICATION, KEY_AOAT_VERIFICATION), profile.getVerificationKeys());
        assertEquals(List.of(SERVICE_AGENT_IDP, SERVICE_AUTHORIZATION_SERVER), profile.getRequiredPeers());
        assertEquals(true, profile.isJwksProviderEnabled());
        
        assertEquals("ES256", profile.getDefaultAlgorithm(KEY_WIT_VERIFICATION));
        assertEquals("RS256", profile.getDefaultAlgorithm(KEY_AOAT_VERIFICATION));
        
        assertEquals(SERVICE_AGENT_IDP, profile.getPeerForKey(KEY_WIT_VERIFICATION));
        assertEquals(SERVICE_AUTHORIZATION_SERVER, profile.getPeerForKey(KEY_AOAT_VERIFICATION));
    }

    @Test
    void testAgentUserIdpProfile() {
        RoleProfile profile = RoleProfileRegistry.getProfile(ROLE_AGENT_USER_IDP);
        
        assertEquals(List.of(KEY_ID_TOKEN_SIGNING), profile.getSigningKeys());
        assertEquals(true, profile.isJwksProviderEnabled());
        
        assertEquals("ES256", profile.getDefaultAlgorithm(KEY_ID_TOKEN_SIGNING));
    }

    @Test
    void testAsUserIdpProfile() {
        RoleProfile profile = RoleProfileRegistry.getProfile(ROLE_AS_USER_IDP);
        
        assertEquals(List.of(KEY_ID_TOKEN_SIGNING), profile.getSigningKeys());
        assertEquals(true, profile.isJwksProviderEnabled());
        
        assertEquals("ES256", profile.getDefaultAlgorithm(KEY_ID_TOKEN_SIGNING));
    }

    @Test
    void testRegistryCannotBeInstantiated() throws Exception {
        var constructor = RoleProfileRegistry.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        assertThrows(java.lang.reflect.InvocationTargetException.class, constructor::newInstance);
    }

    @Test
    void testProfileImmutability() {
        RoleProfile profile = RoleProfileRegistry.getProfile(ROLE_AGENT);
        
        assertThrows(UnsupportedOperationException.class, () -> 
            profile.getSigningKeys().add("new-key")
        );
        
        assertThrows(UnsupportedOperationException.class, () -> 
            profile.getVerificationKeys().add("new-key")
        );
        
        assertThrows(UnsupportedOperationException.class, () -> 
            profile.getEncryptionKeys().add("new-key")
        );
        
        assertThrows(UnsupportedOperationException.class, () -> 
            profile.getDecryptionKeys().add("new-key")
        );
        
        assertThrows(UnsupportedOperationException.class, () -> 
            profile.getRequiredPeers().add("new-peer")
        );
        
        assertThrows(UnsupportedOperationException.class, () -> 
            profile.getRequiredCapabilities().add("new-capability")
        );
        
        assertThrows(UnsupportedOperationException.class, () -> 
            profile.getKeyToPeerMapping().put("new-key", "new-peer")
        );
    }
}
