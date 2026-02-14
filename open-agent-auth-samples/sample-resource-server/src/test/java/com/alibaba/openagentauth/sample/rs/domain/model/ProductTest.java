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
package com.alibaba.openagentauth.sample.rs.domain.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Product domain model.
 */
@DisplayName("Product Model Tests")
class ProductTest {

    @Test
    @DisplayName("Should create product with all fields")
    void shouldCreateProductWithAllFields() {
        Product product = new Product(
                "PROD-001",
                "Test Product",
                "Electronics",
                "A test product",
                new BigDecimal("99.99"),
                "https://example.com/image.jpg"
        );

        assertEquals("PROD-001", product.getId());
        assertEquals("Test Product", product.getName());
        assertEquals("Electronics", product.getCategory());
        assertEquals("A test product", product.getDescription());
        assertEquals(new BigDecimal("99.99"), product.getPrice());
        assertEquals("https://example.com/image.jpg", product.getImageUrl());
    }

    @Test
    @DisplayName("Should return correct string representation")
    void shouldReturnCorrectStringRepresentation() {
        Product product = new Product(
                "PROD-001",
                "Test Product",
                "Electronics",
                "A test product",
                new BigDecimal("99.99"),
                "https://example.com/image.jpg"
        );

        String result = product.toString();

        assertTrue(result.contains("PROD-001"));
        assertTrue(result.contains("Test Product"));
        assertTrue(result.contains("Electronics"));
        assertTrue(result.contains("99.99"));
    }

    @Test
    @DisplayName("Should handle zero price")
    void shouldHandleZeroPrice() {
        Product product = new Product(
                "PROD-002",
                "Free Product",
                "Freebies",
                "A free product",
                BigDecimal.ZERO,
                null
        );

        assertEquals(BigDecimal.ZERO, product.getPrice());
        assertNull(product.getImageUrl());
    }

    @Test
    @DisplayName("Should handle large price")
    void shouldHandleLargePrice() {
        Product product = new Product(
                "PROD-003",
                "Expensive Product",
                "Luxury",
                "An expensive product",
                new BigDecimal("999999.99"),
                null
        );

        assertEquals(new BigDecimal("999999.99"), product.getPrice());
    }

    @Test
    @DisplayName("Should handle empty description")
    void shouldHandleEmptyDescription() {
        Product product = new Product(
                "PROD-004",
                "Minimal Product",
                "Minimal",
                "",
                new BigDecimal("10.00"),
                null
        );

        assertEquals("", product.getDescription());
    }

    @Test
    @DisplayName("Should handle special characters in name")
    void shouldHandleSpecialCharactersInName() {
        Product product = new Product(
                "PROD-005",
                "Product with special-characters & Symbols!",
                "Special",
                "Description with special chars",
                new BigDecimal("50.00"),
                null
        );

        assertEquals("Product with special-characters & Symbols!", product.getName());
    }

    @Test
    @DisplayName("Should handle decimal price with many places")
    void shouldHandleDecimalPriceWithManyPlaces() {
        Product product = new Product(
                "PROD-006",
                "Precise Product",
                "Precision",
                "A product with precise price",
                new BigDecimal("123.456789"),
                null
        );

        assertEquals(new BigDecimal("123.456789"), product.getPrice());
    }
}
