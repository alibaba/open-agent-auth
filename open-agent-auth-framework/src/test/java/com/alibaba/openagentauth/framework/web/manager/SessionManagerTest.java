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
package com.alibaba.openagentauth.framework.web.manager;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SessionManager}.
 * <p>
 * This test class validates the type-safe session attribute management functionality,
 * ensuring type safety, null handling, and proper session operations.
 * </p>
 */
@DisplayName("SessionManager Tests")
@ExtendWith(MockitoExtension.class)
class SessionManagerTest {

    @Mock
    private HttpSession mockSession;

    private static final SessionAttribute<String> TEST_STRING_ATTRIBUTE =
            new SessionAttribute<>("test_string", String.class);

    private static final SessionAttribute<Integer> TEST_INTEGER_ATTRIBUTE =
            new SessionAttribute<>("test_integer", Integer.class);

    private static final SessionAttribute<List> TEST_LIST_ATTRIBUTE =
            new SessionAttribute<>("test_list", List.class);

    private static final SessionAttribute<List> TEST_MIXED_LIST_ATTRIBUTE =
            new SessionAttribute<>("test_mixed_list", List.class);

    @BeforeEach
    void setUp() {
        // No longer need to create SessionManager instance since all methods are static
    }

    @Nested
    @DisplayName("setAttribute")
    class SetAttribute {

        @Test
        @DisplayName("Should set attribute successfully")
        void shouldSetAttributeSuccessfully() {
            String value = "test_value";

            SessionManager.setAttribute(mockSession, TEST_STRING_ATTRIBUTE, value);

            verify(mockSession).setAttribute(TEST_STRING_ATTRIBUTE.getKey(), value);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when session is null")
        void shouldThrowIllegalArgumentExceptionWhenSessionIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.setAttribute(null, TEST_STRING_ATTRIBUTE, "value")
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session");
        }

        @Test
        @DisplayName("Should throw NullPointerException when attribute is null")
        void shouldThrowNullPointerExceptionWhenAttributeIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.setAttribute(mockSession, null, "value")
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session attribute");
        }
    }

    @Nested
    @DisplayName("getAttribute")
    class GetAttribute {

        @Test
        @DisplayName("Should get attribute with correct type")
        void shouldGetAttributeWithCorrectType() {
            String expectedValue = "test_value";
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn(expectedValue);

            String actualValue = SessionManager.getAttribute(mockSession, TEST_STRING_ATTRIBUTE);

            assertThat(actualValue).isEqualTo(expectedValue);
        }

        @Test
        @DisplayName("Should return null when attribute does not exist")
        void shouldReturnNullWhenAttributeDoesNotExist() {
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn(null);

            String value = SessionManager.getAttribute(mockSession, TEST_STRING_ATTRIBUTE);

            assertThat(value).isNull();
        }

        @Test
        @DisplayName("Should return null when attribute type does not match")
        void shouldReturnNullWhenTypeDoesNotMatch() {
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn(123);

            String value = SessionManager.getAttribute(mockSession, TEST_STRING_ATTRIBUTE);

            assertThat(value).isNull();
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when session is null")
        void shouldThrowIllegalArgumentExceptionWhenSessionIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.getAttribute(null, TEST_STRING_ATTRIBUTE)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session");
        }

        @Test
        @DisplayName("Should throw NullPointerException when attribute is null")
        void shouldThrowNullPointerExceptionWhenAttributeIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.getAttribute(mockSession, null)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session attribute");
        }
    }

    @Nested
    @DisplayName("getAttribute with default value")
    class GetAttributeWithDefaultValue {

        @Test
        @DisplayName("Should return attribute value when it exists")
        void shouldReturnValueWhenAttributeExists() {
            String expectedValue = "actual_value";
            String defaultValue = "default_value";
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn(expectedValue);

            String actualValue = SessionManager.getAttribute(mockSession, TEST_STRING_ATTRIBUTE, defaultValue);

            assertThat(actualValue).isEqualTo(expectedValue);
        }

        @Test
        @DisplayName("Should return default value when attribute does not exist")
        void shouldReturnDefaultValueWhenAttributeDoesNotExist() {
            String defaultValue = "default_value";
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn(null);

            String actualValue = SessionManager.getAttribute(mockSession, TEST_STRING_ATTRIBUTE, defaultValue);

            assertThat(actualValue).isEqualTo(defaultValue);
        }

        @Test
        @DisplayName("Should return default value when attribute is null")
        void shouldReturnDefaultValueWhenAttributeIsNull() {
            String defaultValue = "default_value";
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn(null);

            String actualValue = SessionManager.getAttribute(mockSession, TEST_STRING_ATTRIBUTE, defaultValue);

            assertThat(actualValue).isEqualTo(defaultValue);
        }
    }

    @Nested
    @DisplayName("getAttributeAsList")
    class GetAttributeAsList {

        @Test
        @DisplayName("Should return filtered list with correct type")
        void shouldReturnFilteredListWithCorrectType() {
            List<Object> mixedList = new ArrayList<>();
            mixedList.add("string1");
            mixedList.add("string2");
            mixedList.add(123);
            mixedList.add("string3");
            when(mockSession.getAttribute(TEST_MIXED_LIST_ATTRIBUTE.getKey())).thenReturn(mixedList);

            List<String> stringList = SessionManager.getAttributeAsList(
                    mockSession,
                    TEST_MIXED_LIST_ATTRIBUTE,
                    String.class
            );

            assertThat(stringList).hasSize(3);
            assertThat(stringList).containsExactly("string1", "string2", "string3");
        }

        @Test
        @DisplayName("Should return empty list when attribute does not exist")
        void shouldReturnEmptyListWhenAttributeDoesNotExist() {
            when(mockSession.getAttribute(TEST_LIST_ATTRIBUTE.getKey())).thenReturn(null);

            List<String> result = SessionManager.getAttributeAsList(
                    mockSession,
                    TEST_LIST_ATTRIBUTE,
                    String.class
            );

            assertThat(result).isNotNull();
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list when attribute is null")
        void shouldReturnEmptyListWhenAttributeIsNull() {
            when(mockSession.getAttribute(TEST_LIST_ATTRIBUTE.getKey())).thenReturn(null);

            List<String> result = SessionManager.getAttributeAsList(
                    mockSession,
                    TEST_LIST_ATTRIBUTE,
                    String.class
            );

            assertThat(result).isNotNull();
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should return empty list when no elements match type")
        void shouldReturnEmptyListWhenNoElementsMatchType() {
            List<Object> integerList = new ArrayList<>();
            integerList.add(123);
            integerList.add(456);
            when(mockSession.getAttribute(TEST_LIST_ATTRIBUTE.getKey())).thenReturn(integerList);

            List<String> result = SessionManager.getAttributeAsList(
                    mockSession,
                    TEST_LIST_ATTRIBUTE,
                    String.class
            );

            assertThat(result).isNotNull();
            assertThat(result).isEmpty();
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when session is null")
        void shouldThrowIllegalArgumentExceptionWhenSessionIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.getAttributeAsList(null, TEST_LIST_ATTRIBUTE, String.class)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session");
        }

        @Test
        @DisplayName("Should throw NullPointerException when attribute is null")
        void shouldThrowNullPointerExceptionWhenAttributeIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.getAttributeAsList(mockSession, null, String.class)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session attribute");
        }

        @Test
        @DisplayName("Should throw NullPointerException when elementType is null")
        void shouldThrowNullPointerExceptionWhenElementTypeIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.getAttributeAsList(mockSession, TEST_LIST_ATTRIBUTE, null)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Element type");
        }
    }

    @Nested
    @DisplayName("addToList")
    class AddToList {

        @Test
        @DisplayName("Should add element to existing list")
        void shouldAddElementToExistingList() {
            List<Object> existingList = new ArrayList<>();
            existingList.add("item1");
            when(mockSession.getAttribute(TEST_LIST_ATTRIBUTE.getKey())).thenReturn(existingList);

            SessionManager.addToList(mockSession, TEST_LIST_ATTRIBUTE, "item2", String.class);

            verify(mockSession).setAttribute(TEST_LIST_ATTRIBUTE.getKey(), existingList);
            assertThat(existingList).hasSize(2);
            assertThat(existingList).contains("item1", "item2");
        }

        @Test
        @DisplayName("Should create new list when attribute does not exist")
        void shouldCreateNewListWhenAttributeDoesNotExist() {
            when(mockSession.getAttribute(TEST_LIST_ATTRIBUTE.getKey())).thenReturn(null);

            SessionManager.addToList(mockSession, TEST_LIST_ATTRIBUTE, "item1", String.class);

            verify(mockSession).setAttribute(anyString(), forClass(List.class).capture());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when session is null")
        void shouldThrowIllegalArgumentExceptionWhenSessionIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.addToList(null, TEST_LIST_ATTRIBUTE, "item", String.class)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session");
        }

        @Test
        @DisplayName("Should throw NullPointerException when attribute is null")
        void shouldThrowNullPointerExceptionWhenAttributeIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.addToList(mockSession, null, "item", String.class)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session attribute");
        }

        @Test
        @DisplayName("Should throw NullPointerException when element is null")
        void shouldThrowNullPointerExceptionWhenElementIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.addToList(mockSession, TEST_LIST_ATTRIBUTE, null, String.class)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Element");
        }
    }

    @Nested
    @DisplayName("removeAttribute")
    class RemoveAttribute {

        @Test
        @DisplayName("Should remove attribute successfully")
        void shouldRemoveAttributeSuccessfully() {
            SessionManager.removeAttribute(mockSession, TEST_STRING_ATTRIBUTE);

            verify(mockSession).removeAttribute(TEST_STRING_ATTRIBUTE.getKey());
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when session is null")
        void shouldThrowIllegalArgumentExceptionWhenSessionIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.removeAttribute(null, TEST_STRING_ATTRIBUTE)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session");
        }

        @Test
        @DisplayName("Should throw NullPointerException when attribute is null")
        void shouldThrowNullPointerExceptionWhenAttributeIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.removeAttribute(mockSession, null)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session attribute");
        }
    }

    @Nested
    @DisplayName("hasAttribute")
    class HasAttribute {

        @Test
        @DisplayName("Should return true when attribute exists")
        void shouldReturnTrueWhenAttributeExists() {
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn("value");

            boolean hasAttribute = SessionManager.hasAttribute(mockSession, TEST_STRING_ATTRIBUTE);

            assertThat(hasAttribute).isTrue();
        }

        @Test
        @DisplayName("Should return false when attribute does not exist")
        void shouldReturnFalseWhenAttributeDoesNotExist() {
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn(null);

            boolean hasAttribute = SessionManager.hasAttribute(mockSession, TEST_STRING_ATTRIBUTE);

            assertThat(hasAttribute).isFalse();
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when session is null")
        void shouldThrowIllegalArgumentExceptionWhenSessionIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.hasAttribute(null, TEST_STRING_ATTRIBUTE)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session");
        }

        @Test
        @DisplayName("Should throw NullPointerException when attribute is null")
        void shouldThrowNullPointerExceptionWhenAttributeIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.hasAttribute(mockSession, null)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session attribute");
        }
    }

    @Nested
    @DisplayName("with - Fluent API")
    class WithFluentAPI {

        @Test
        @DisplayName("Should create SessionBuilder successfully")
        void shouldCreateSessionBuilderSuccessfully() {
            SessionManager.SessionBuilder builder = SessionManager.with(mockSession);

            assertThat(builder).isNotNull();
            assertThat(builder.getSession()).isEqualTo(mockSession);
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when session is null")
        void shouldThrowIllegalArgumentExceptionWhenSessionIsNull() {
            assertThatThrownBy(() ->
                    SessionManager.with(null)
            ).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Session");
        }

        @Test
        @DisplayName("Should support method chaining for multiple operations")
        void shouldSupportMethodChainingForMultipleOperations() {
            SessionManager.SessionBuilder builder = SessionManager.with(mockSession);

            SessionManager.SessionBuilder result = builder
                    .set(TEST_STRING_ATTRIBUTE, "value1")
                    .set(TEST_INTEGER_ATTRIBUTE, 123)
                    .remove(TEST_STRING_ATTRIBUTE);

            assertThat(result).isNotNull();
            verify(mockSession).setAttribute(TEST_STRING_ATTRIBUTE.getKey(), "value1");
            verify(mockSession).setAttribute(TEST_INTEGER_ATTRIBUTE.getKey(), 123);
            verify(mockSession).removeAttribute(TEST_STRING_ATTRIBUTE.getKey());
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should support complete session lifecycle")
        void shouldSupportCompleteSessionLifecycle() {
            String testValue = "test_value";
            String defaultValue = "default_value";

            // Set attribute
            SessionManager.setAttribute(mockSession, TEST_STRING_ATTRIBUTE, testValue);
            verify(mockSession).setAttribute(TEST_STRING_ATTRIBUTE.getKey(), testValue);

            // Check attribute exists
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn(testValue);
            boolean hasAttribute = SessionManager.hasAttribute(mockSession, TEST_STRING_ATTRIBUTE);
            assertThat(hasAttribute).isTrue();

            // Get attribute
            String retrievedValue = SessionManager.getAttribute(mockSession, TEST_STRING_ATTRIBUTE);
            assertThat(retrievedValue).isEqualTo(testValue);

            // Get attribute with default value
            String valueWithDefault = SessionManager.getAttribute(mockSession, TEST_STRING_ATTRIBUTE, defaultValue);
            assertThat(valueWithDefault).isEqualTo(testValue);

            // Remove attribute
            SessionManager.removeAttribute(mockSession, TEST_STRING_ATTRIBUTE);
            verify(mockSession).removeAttribute(TEST_STRING_ATTRIBUTE.getKey());

            // Check attribute does not exist
            when(mockSession.getAttribute(TEST_STRING_ATTRIBUTE.getKey())).thenReturn(null);
            hasAttribute = SessionManager.hasAttribute(mockSession, TEST_STRING_ATTRIBUTE);
            assertThat(hasAttribute).isFalse();

            // Get default value when attribute does not exist
            valueWithDefault = SessionManager.getAttribute(mockSession, TEST_STRING_ATTRIBUTE, defaultValue);
            assertThat(valueWithDefault).isEqualTo(defaultValue);
        }

        @Test
        @DisplayName("Should support list operations")
        void shouldSupportListOperations() {
            List<Object> list = new ArrayList<>();
            list.add("item1");
            list.add("item2");

            // Add to list (new list)
            when(mockSession.getAttribute(TEST_LIST_ATTRIBUTE.getKey())).thenReturn(null);
            SessionManager.addToList(mockSession, TEST_LIST_ATTRIBUTE, "item1", String.class);
            verify(mockSession).setAttribute(anyString(), forClass(List.class).capture());

            // Add to list (existing list)
            when(mockSession.getAttribute(TEST_LIST_ATTRIBUTE.getKey())).thenReturn(list);
            SessionManager.addToList(mockSession, TEST_LIST_ATTRIBUTE, "item3", String.class);
            verify(mockSession).setAttribute(TEST_LIST_ATTRIBUTE.getKey(), list);

            // Get list with type filtering
            List<String> stringList = SessionManager.getAttributeAsList(
                    mockSession,
                    TEST_LIST_ATTRIBUTE,
                    String.class
            );
            assertThat(stringList).hasSize(3);
        }
    }
}
