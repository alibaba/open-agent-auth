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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Cart domain model.
 */
@DisplayName("Cart Model Tests")
class CartTest {

    private Cart cart;

    @BeforeEach
    void setUp() {
        cart = new Cart("user123");
    }

    @Test
    @DisplayName("Should create cart with user ID")
    void shouldCreateCartWithUserId() {
        assertEquals("user123", cart.getUserId());
        assertTrue(cart.isEmpty());
        assertEquals(0, cart.getTotalItemCount());
        assertEquals(BigDecimal.ZERO, cart.getTotalPrice());
    }

    @Test
    @DisplayName("Should add item to cart")
    void shouldAddItemToCart() {
        cart.addItem("PROD-001", "Test Product", 2, new BigDecimal("99.99"));

        assertFalse(cart.isEmpty());
        assertEquals(1, cart.getItems().size());
        assertEquals(2, cart.getTotalItemCount());
        assertEquals(new BigDecimal("199.98"), cart.getTotalPrice());
    }

    @Test
    @DisplayName("Should add multiple items to cart")
    void shouldAddMultipleItemsToCart() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));
        cart.addItem("PROD-002", "Product 2", 1, new BigDecimal("199.99"));

        assertEquals(2, cart.getItems().size());
        assertEquals(3, cart.getTotalItemCount());
        assertEquals(new BigDecimal("399.97"), cart.getTotalPrice());
    }

    @Test
    @DisplayName("Should update quantity when adding same product")
    void shouldUpdateQuantityWhenAddingSameProduct() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));
        cart.addItem("PROD-001", "Product 1", 1, new BigDecimal("99.99"));

        assertEquals(1, cart.getItems().size());
        assertEquals(3, cart.getTotalItemCount());
        assertEquals(new BigDecimal("299.97"), cart.getTotalPrice());
    }

    @Test
    @DisplayName("Should remove item from cart")
    void shouldRemoveItemFromCart() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));
        cart.addItem("PROD-002", "Product 2", 1, new BigDecimal("199.99"));

        cart.removeItem("PROD-001");

        assertEquals(1, cart.getItems().size());
        assertEquals(1, cart.getTotalItemCount());
        assertEquals(new BigDecimal("199.99"), cart.getTotalPrice());
    }

    @Test
    @DisplayName("Should update quantity of item")
    void shouldUpdateQuantityOfItem() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));

        cart.updateQuantity("PROD-001", 5);

        assertEquals(5, cart.getItems().get(0).getQuantity());
        assertEquals(5, cart.getTotalItemCount());
        assertEquals(new BigDecimal("499.95"), cart.getTotalPrice());
    }

    @Test
    @DisplayName("Should remove item when updating quantity to zero")
    void shouldRemoveItemWhenUpdatingQuantityToZero() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));

        cart.updateQuantity("PROD-001", 0);

        assertTrue(cart.isEmpty());
        assertEquals(0, cart.getTotalItemCount());
    }

    @Test
    @DisplayName("Should remove item when updating quantity to negative")
    void shouldRemoveItemWhenUpdatingQuantityToNegative() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));

        cart.updateQuantity("PROD-001", -1);

        assertTrue(cart.isEmpty());
        assertEquals(0, cart.getTotalItemCount());
    }

    @Test
    @DisplayName("Should clear all items from cart")
    void shouldClearAllItemsFromCart() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));
        cart.addItem("PROD-002", "Product 2", 1, new BigDecimal("199.99"));

        cart.clear();

        assertTrue(cart.isEmpty());
        assertEquals(0, cart.getItems().size());
        assertEquals(0, cart.getTotalItemCount());
        assertEquals(BigDecimal.ZERO, cart.getTotalPrice());
    }

    @Test
    @DisplayName("Should get items list")
    void shouldGetItemsList() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));
        cart.addItem("PROD-002", "Product 2", 1, new BigDecimal("199.99"));

        List<Cart.CartItem> items = cart.getItems();

        assertEquals(2, items.size());
    }

    @Test
    @DisplayName("Items list should be immutable")
    void itemsListShouldBeImmutable() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));
        List<Cart.CartItem> items = cart.getItems();

        items.clear();

        assertEquals(1, cart.getItems().size());
    }

    @Test
    @DisplayName("Should calculate total price correctly")
    void shouldCalculateTotalPriceCorrectly() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));
        cart.addItem("PROD-002", "Product 2", 3, new BigDecimal("199.99"));

        BigDecimal expected = new BigDecimal("99.99").multiply(BigDecimal.valueOf(2))
                .add(new BigDecimal("199.99").multiply(BigDecimal.valueOf(3)));
        assertEquals(expected, cart.getTotalPrice());
    }

    @Test
    @DisplayName("Should calculate total item count correctly")
    void shouldCalculateTotalItemCountCorrectly() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));
        cart.addItem("PROD-002", "Product 2", 3, new BigDecimal("199.99"));

        assertEquals(5, cart.getTotalItemCount());
    }

    @Test
    @DisplayName("CartItem should calculate total price")
    void cartItemShouldCalculateTotalPrice() {
        Cart.CartItem item = new Cart.CartItem("PROD-001", "Product", 3, new BigDecimal("99.99"));

        assertEquals(new BigDecimal("299.97"), item.getTotalPrice());
    }

    @Test
    @DisplayName("CartItem should have correct getters")
    void cartItemShouldHaveCorrectGetters() {
        Cart.CartItem item = new Cart.CartItem("PROD-001", "Product", 2, new BigDecimal("99.99"));

        assertEquals("PROD-001", item.getProductId());
        assertEquals("Product", item.getProductName());
        assertEquals(2, item.getQuantity());
        assertEquals(new BigDecimal("99.99"), item.getUnitPrice());
    }

    @Test
    @DisplayName("Should return correct string representation")
    void shouldReturnCorrectStringRepresentation() {
        cart.addItem("PROD-001", "Product 1", 2, new BigDecimal("99.99"));

        String result = cart.toString();

        assertTrue(result.contains("user123"));
        assertTrue(result.contains("2"));
        assertTrue(result.contains("199.98"));
    }
}