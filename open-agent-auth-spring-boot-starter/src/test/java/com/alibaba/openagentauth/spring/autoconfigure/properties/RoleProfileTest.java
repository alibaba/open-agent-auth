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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link RoleProfile}.
 *
 * @since 2.1
 */
@SpringBootTest(classes = TestConfiguration.class)
class RoleProfileTest {

    @Test
    void testBuilderPattern() {
        RoleProfile profile = RoleProfile.builder()
                .signingKeys("key1", "key2")
                .verificationKeys("key3")
                .encryptionKeys("key4")
                .decryptionKeys("key5")
                .requiredPeers("peer1", "peer2")
                .requiredCapabilities("capability1")
                .jwksProviderEnabled(false)
                .keyDefaultAlgorithms(Map.of("key1", "ES256"))
                .keyToPeerMapping(Map.of("key3", "peer1"))
                .build();
        
        assertEquals(List.of("key1", "key2"), profile.getSigningKeys());
        assertEquals(List.of("key3"), profile.getVerificationKeys());
        assertEquals(List.of("key4"), profile.getEncryptionKeys());
        assertEquals(List.of("key5"), profile.getDecryptionKeys());
        assertEquals(List.of("peer1", "peer2"), profile.getRequiredPeers());
        assertEquals(List.of("capability1"), profile.getRequiredCapabilities());
        assertEquals(false, profile.isJwksProviderEnabled());
    }

    @Test
    void testImmutabilityReturnsUnmodifiableList() {
        RoleProfile profile = RoleProfile.builder()
                .signingKeys("key1", "key2")
                .verificationKeys("key3")
                .build();
        
        List<String> signingKeys = profile.getSigningKeys();
        assertThrows(UnsupportedOperationException.class, () -> signingKeys.add("new-key"));
        
        List<String> verificationKeys = profile.getVerificationKeys();
        assertThrows(UnsupportedOperationException.class, () -> verificationKeys.add("new-key"));
        
        List<String> encryptionKeys = profile.getEncryptionKeys();
        assertThrows(UnsupportedOperationException.class, () -> encryptionKeys.add("new-key"));
        
        List<String> decryptionKeys = profile.getDecryptionKeys();
        assertThrows(UnsupportedOperationException.class, () -> decryptionKeys.add("new-key"));
        
        List<String> requiredPeers = profile.getRequiredPeers();
        assertThrows(UnsupportedOperationException.class, () -> requiredPeers.add("new-peer"));
        
        List<String> requiredCapabilities = profile.getRequiredCapabilities();
        assertThrows(UnsupportedOperationException.class, () -> requiredCapabilities.add("new-capability"));
    }

    @Test
    void testImmutabilityReturnsUnmodifiableMap() {
        RoleProfile profile = RoleProfile.builder()
                .keyDefaultAlgorithms(Map.of("key1", "ES256"))
                .keyToPeerMapping(Map.of("key1", "peer1"))
                .build();
        
        Map<String, String> keyDefaultAlgorithms = profile.getKeyToPeerMapping();
        assertThrows(UnsupportedOperationException.class, () -> keyDefaultAlgorithms.put("new-key", "new-value"));
        
        Map<String, String> keyToPeerMapping = profile.getKeyToPeerMapping();
        assertThrows(UnsupportedOperationException.class, () -> keyToPeerMapping.put("new-key", "new-peer"));
    }

    @Test
    void testGetDefaultAlgorithm() {
        Map<String, String> algorithms = new HashMap<>();
        algorithms.put("wit-signing", "ES256");
        algorithms.put("par-jwt-signing", "RS256");
        
        RoleProfile profile = RoleProfile.builder()
                .keyDefaultAlgorithms(algorithms)
                .build();
        
        assertEquals("ES256", profile.getDefaultAlgorithm("wit-signing"));
        assertEquals("RS256", profile.getDefaultAlgorithm("par-jwt-signing"));
        assertNull(profile.getDefaultAlgorithm("unknown-key"));
    }

    @Test
    void testGetPeerForKey() {
        Map<String, String> mapping = new HashMap<>();
        mapping.put("wit-verification", "agent-idp");
        mapping.put("id-token-verification", "agent-user-idp");
        
        RoleProfile profile = RoleProfile.builder()
                .keyToPeerMapping(mapping)
                .build();
        
        assertEquals("agent-idp", profile.getPeerForKey("wit-verification"));
        assertEquals("agent-user-idp", profile.getPeerForKey("id-token-verification"));
        assertNull(profile.getPeerForKey("local-key"));
    }

    @Test
    void testAllFieldGetters() {
        RoleProfile profile = RoleProfile.builder()
                .signingKeys("sign-key1", "sign-key2")
                .verificationKeys("verify-key")
                .encryptionKeys("encrypt-key")
                .decryptionKeys("decrypt-key")
                .requiredPeers("peer1", "peer2")
                .requiredCapabilities("cap1", "cap2")
                .jwksProviderEnabled(true)
                .keyDefaultAlgorithms(Map.of("key1", "ES256"))
                .keyToPeerMapping(Map.of("key2", "peer1"))
                .build();
        
        assertEquals(List.of("sign-key1", "sign-key2"), profile.getSigningKeys());
        assertEquals(List.of("verify-key"), profile.getVerificationKeys());
        assertEquals(List.of("encrypt-key"), profile.getEncryptionKeys());
        assertEquals(List.of("decrypt-key"), profile.getDecryptionKeys());
        assertEquals(List.of("peer1", "peer2"), profile.getRequiredPeers());
        assertEquals(List.of("cap1", "cap2"), profile.getRequiredCapabilities());
        assertEquals(true, profile.isJwksProviderEnabled());
        assertEquals("ES256", profile.getDefaultAlgorithm("key1"));
        assertEquals("peer1", profile.getPeerForKey("key2"));
    }

    @Test
    void testBuilderWithEmptyCollections() {
        RoleProfile profile = RoleProfile.builder()
                .build();
        
        assertNotNull(profile.getSigningKeys());
        assertTrue(profile.getSigningKeys().isEmpty());
        
        assertNotNull(profile.getVerificationKeys());
        assertTrue(profile.getVerificationKeys().isEmpty());
        
        assertNotNull(profile.getEncryptionKeys());
        assertTrue(profile.getEncryptionKeys().isEmpty());
        
        assertNotNull(profile.getDecryptionKeys());
        assertTrue(profile.getDecryptionKeys().isEmpty());
        
        assertNotNull(profile.getRequiredPeers());
        assertTrue(profile.getRequiredPeers().isEmpty());
        
        assertNotNull(profile.getRequiredCapabilities());
        assertTrue(profile.getRequiredCapabilities().isEmpty());
        
        assertNotNull(profile.getKeyToPeerMapping());
        assertTrue(profile.getKeyToPeerMapping().isEmpty());
    }

    @Test
    void testBuilderDefaultValues() {
        RoleProfile profile = RoleProfile.builder()
                .build();
        
        assertEquals(true, profile.isJwksProviderEnabled());
    }

    @Test
    void testBuilderRequiresNonNullForMaps() {
        assertThrows(NullPointerException.class, () -> 
            RoleProfile.builder()
                .keyDefaultAlgorithms(null)
                .build()
        );
        
        assertThrows(NullPointerException.class, () -> 
            RoleProfile.builder()
                .keyToPeerMapping(null)
                .build()
        );
    }
}
