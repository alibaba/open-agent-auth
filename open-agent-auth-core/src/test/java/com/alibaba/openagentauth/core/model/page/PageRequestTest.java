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
package com.alibaba.openagentauth.core.model.page;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PageRequest}.
 * <p>
 * Tests cover default values, valid values, invalid values, maximum size limits,
 * offset calculations, and getter/setter functionality.
 * </p>
 */
@DisplayName("PageRequest Tests")
class PageRequestTest {

    @Nested
    @DisplayName("getEffectivePage() Tests")
    class GetEffectivePageTests {

        @Test
        @DisplayName("Should return default page 1 when page is null")
        void shouldReturnDefaultPageWhenPageIsNull() {
            // Arrange
            PageRequest pageRequest = new PageRequest(null, 10);

            // Act
            int effectivePage = pageRequest.getEffectivePage();

            // Assert
            assertThat(effectivePage).isEqualTo(1);
        }

        @Test
        @DisplayName("Should return default page 1 when page is 0")
        void shouldReturnDefaultPageWhenPageIsZero() {
            // Arrange
            PageRequest pageRequest = new PageRequest(0, 10);

            // Act
            int effectivePage = pageRequest.getEffectivePage();

            // Assert
            assertThat(effectivePage).isEqualTo(1);
        }

        @Test
        @DisplayName("Should return default page 1 when page is negative")
        void shouldReturnDefaultPageWhenPageIsNegative() {
            // Arrange
            PageRequest pageRequest = new PageRequest(-1, 10);

            // Act
            int effectivePage = pageRequest.getEffectivePage();

            // Assert
            assertThat(effectivePage).isEqualTo(1);
        }

        @Test
        @DisplayName("Should return the actual page when page is valid")
        void shouldReturnActualPageWhenPageIsValid() {
            // Arrange
            PageRequest pageRequest = new PageRequest(3, 10);

            // Act
            int effectivePage = pageRequest.getEffectivePage();

            // Assert
            assertThat(effectivePage).isEqualTo(3);
        }
    }

    @Nested
    @DisplayName("getEffectiveSize() Tests")
    class GetEffectiveSizeTests {

        @Test
        @DisplayName("Should return default size 20 when size is null")
        void shouldReturnDefaultSizeWhenSizeIsNull() {
            // Arrange
            PageRequest pageRequest = new PageRequest(1, null);

            // Act
            int effectiveSize = pageRequest.getEffectiveSize();

            // Assert
            assertThat(effectiveSize).isEqualTo(20);
        }

        @Test
        @DisplayName("Should return default size 20 when size is 0")
        void shouldReturnDefaultSizeWhenSizeIsZero() {
            // Arrange
            PageRequest pageRequest = new PageRequest(1, 0);

            // Act
            int effectiveSize = pageRequest.getEffectiveSize();

            // Assert
            assertThat(effectiveSize).isEqualTo(20);
        }

        @Test
        @DisplayName("Should return default size 20 when size is negative")
        void shouldReturnDefaultSizeWhenSizeIsNegative() {
            // Arrange
            PageRequest pageRequest = new PageRequest(1, -1);

            // Act
            int effectiveSize = pageRequest.getEffectiveSize();

            // Assert
            assertThat(effectiveSize).isEqualTo(20);
        }

        @Test
        @DisplayName("Should return the actual size when size is valid")
        void shouldReturnActualSizeWhenSizeIsValid() {
            // Arrange
            PageRequest pageRequest = new PageRequest(1, 10);

            // Act
            int effectiveSize = pageRequest.getEffectiveSize();

            // Assert
            assertThat(effectiveSize).isEqualTo(10);
        }

        @Test
        @DisplayName("Should cap size at MAX_SIZE (100) when size exceeds limit")
        void shouldCapSizeAtMaxSizeWhenSizeExceedsLimit() {
            // Arrange
            PageRequest pageRequest = new PageRequest(1, 200);

            // Act
            int effectiveSize = pageRequest.getEffectiveSize();

            // Assert
            assertThat(effectiveSize).isEqualTo(100);
        }
    }

    @Nested
    @DisplayName("getOffset() Tests")
    class GetOffsetTests {

        @Test
        @DisplayName("Should return 0 for page 1 and size 20")
        void shouldReturnZeroForFirstPage() {
            // Arrange
            PageRequest pageRequest = new PageRequest(1, 20);

            // Act
            int offset = pageRequest.getOffset();

            // Assert
            assertThat(offset).isEqualTo(0);
        }

        @Test
        @DisplayName("Should return 20 for page 3 and size 10")
        void shouldReturnCorrectOffsetForThirdPage() {
            // Arrange
            PageRequest pageRequest = new PageRequest(3, 10);

            // Act
            int offset = pageRequest.getOffset();

            // Assert
            assertThat(offset).isEqualTo(20);
        }
    }

    @Nested
    @DisplayName("Getter and Setter Tests")
    class GetterSetterTests {

        @Test
        @DisplayName("Should set and get page correctly")
        void shouldSetAndGetPageCorrectly() {
            // Arrange
            PageRequest pageRequest = new PageRequest();

            // Act
            pageRequest.setPage(5);
            Integer page = pageRequest.getPage();

            // Assert
            assertThat(page).isEqualTo(5);
        }

        @Test
        @DisplayName("Should set and get size correctly")
        void shouldSetAndGetSizeCorrectly() {
            // Arrange
            PageRequest pageRequest = new PageRequest();

            // Act
            pageRequest.setSize(30);
            Integer size = pageRequest.getSize();

            // Assert
            assertThat(size).isEqualTo(30);
        }
    }
}
