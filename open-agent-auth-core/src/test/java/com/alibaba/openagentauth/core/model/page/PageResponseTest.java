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

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link PageResponse}.
 * <p>
 * Tests cover empty/null lists, normal pagination, edge cases (last page, out of range),
 * single page scenarios, and getter/setter functionality.
 * </p>
 */
@DisplayName("PageResponse Tests")
class PageResponseTest {

    @Nested
    @DisplayName("of() Factory Method Tests")
    class OfFactoryMethodTests {

        @Test
        @DisplayName("Should return empty page when list is empty")
        void shouldReturnEmptyPageWhenListIsEmpty() {
            // Arrange
            List<String> emptyList = List.of();
            PageRequest pageRequest = new PageRequest(1, 10);

            // Act
            PageResponse<String> response = PageResponse.of(emptyList, pageRequest);

            // Assert
            assertThat(response.getItems()).isEmpty();
            assertThat(response.getTotalItems()).isEqualTo(0);
            assertThat(response.getTotalPages()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should return empty page when list is null")
        void shouldReturnEmptyPageWhenListIsNull() {
            // Arrange
            PageRequest pageRequest = new PageRequest(1, 10);

            // Act
            PageResponse<String> response = PageResponse.of(null, pageRequest);

            // Assert
            assertThat(response.getItems()).isEmpty();
            assertThat(response.getTotalItems()).isEqualTo(0);
            assertThat(response.getTotalPages()).isEqualTo(0);
        }

        @Test
        @DisplayName("Should return first page with 10 items from 25 total items")
        void shouldReturnFirstPageWithCorrectItems() {
            // Arrange
            List<Integer> items = createList(25);
            PageRequest pageRequest = new PageRequest(1, 10);

            // Act
            PageResponse<Integer> response = PageResponse.of(items, pageRequest);

            // Assert
            assertThat(response.getItems()).hasSize(10);
            assertThat(response.getItems()).containsExactly(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
            assertThat(response.getTotalItems()).isEqualTo(25);
            assertThat(response.getTotalPages()).isEqualTo(3);
        }

        @Test
        @DisplayName("Should return second page with 10 items from 25 total items")
        void shouldReturnSecondPageWithCorrectItems() {
            // Arrange
            List<Integer> items = createList(25);
            PageRequest pageRequest = new PageRequest(2, 10);

            // Act
            PageResponse<Integer> response = PageResponse.of(items, pageRequest);

            // Assert
            assertThat(response.getItems()).hasSize(10);
            assertThat(response.getItems()).containsExactly(11, 12, 13, 14, 15, 16, 17, 18, 19, 20);
            assertThat(response.getTotalItems()).isEqualTo(25);
        }

        @Test
        @DisplayName("Should return last page with 5 items from 25 total items")
        void shouldReturnLastPageWithRemainingItems() {
            // Arrange
            List<Integer> items = createList(25);
            PageRequest pageRequest = new PageRequest(3, 10);

            // Act
            PageResponse<Integer> response = PageResponse.of(items, pageRequest);

            // Assert
            assertThat(response.getItems()).hasSize(5);
            assertThat(response.getItems()).containsExactly(21, 22, 23, 24, 25);
            assertThat(response.getTotalItems()).isEqualTo(25);
            assertThat(response.getTotalPages()).isEqualTo(3);
        }

        @Test
        @DisplayName("Should return empty items when page is out of range")
        void shouldReturnEmptyItemsWhenPageIsOutOfRange() {
            // Arrange
            List<Integer> items = createList(25);
            PageRequest pageRequest = new PageRequest(5, 10);

            // Act
            PageResponse<Integer> response = PageResponse.of(items, pageRequest);

            // Assert
            assertThat(response.getItems()).isEmpty();
            assertThat(response.getTotalItems()).isEqualTo(25);
            assertThat(response.getTotalPages()).isEqualTo(3);
        }

        @Test
        @DisplayName("Should return all items on single page when items fit")
        void shouldReturnAllItemsOnSinglePage() {
            // Arrange
            List<Integer> items = createList(5);
            PageRequest pageRequest = new PageRequest(1, 20);

            // Act
            PageResponse<Integer> response = PageResponse.of(items, pageRequest);

            // Assert
            assertThat(response.getItems()).hasSize(5);
            assertThat(response.getItems()).containsExactly(1, 2, 3, 4, 5);
            assertThat(response.getTotalItems()).isEqualTo(5);
            assertThat(response.getTotalPages()).isEqualTo(1);
        }
    }

    @Nested
    @DisplayName("Getter and Setter Tests")
    class GetterSetterTests {

        @Test
        @DisplayName("Should set and get items correctly")
        void shouldSetAndGetItemsCorrectly() {
            // Arrange
            PageResponse<String> response = new PageResponse<>();
            List<String> items = List.of("item1", "item2");

            // Act
            response.setItems(items);

            // Assert
            assertThat(response.getItems()).isEqualTo(items);
        }

        @Test
        @DisplayName("Should set and get page correctly")
        void shouldSetAndGetPageCorrectly() {
            // Arrange
            PageResponse<String> response = new PageResponse<>();

            // Act
            response.setPage(2);

            // Assert
            assertThat(response.getPage()).isEqualTo(2);
        }

        @Test
        @DisplayName("Should set and get size correctly")
        void shouldSetGetSizeCorrectly() {
            // Arrange
            PageResponse<String> response = new PageResponse<>();

            // Act
            response.setSize(15);

            // Assert
            assertThat(response.getSize()).isEqualTo(15);
        }

        @Test
        @DisplayName("Should set and get totalItems correctly")
        void shouldSetAndGetTotalItemsCorrectly() {
            // Arrange
            PageResponse<String> response = new PageResponse<>();

            // Act
            response.setTotalItems(100L);

            // Assert
            assertThat(response.getTotalItems()).isEqualTo(100L);
        }

        @Test
        @DisplayName("Should set and get totalPages correctly")
        void shouldSetAndGetTotalPagesCorrectly() {
            // Arrange
            PageResponse<String> response = new PageResponse<>();

            // Act
            response.setTotalPages(10);

            // Assert
            assertThat(response.getTotalPages()).isEqualTo(10);
        }
    }

    /**
     * Helper method to create a list of integers from 1 to n.
     *
     * @param n the number of items to create
     * @return a list containing integers 1 through n
     */
    private List<Integer> createList(int n) {
        List<Integer> list = new ArrayList<>(n);
        for (int i = 1; i <= n; i++) {
            list.add(i);
        }
        return list;
    }
}
