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
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Order domain model.
 */
@DisplayName("Order Model Tests")
class OrderTest {

    @Test
    @DisplayName("Should create order with all fields")
    void shouldCreateOrderWithAllFields() {
        LocalDateTime now = LocalDateTime.now();
        Order.OrderItem item = new Order.OrderItem("PROD-001", "Product", 2, new BigDecimal("99.99"));
        Order order = new Order("ORDER-001", "user123", List.of(item), Order.OrderStatus.PROCESSING, now);

        assertEquals("ORDER-001", order.getId());
        assertEquals("user123", order.getUserId());
        assertEquals(1, order.getItems().size());
        assertEquals(Order.OrderStatus.PROCESSING, order.getStatus());
        assertEquals(now, order.getCreatedAt());
        assertEquals(new BigDecimal("199.98"), order.getTotalAmount());
    }

    @Test
    @DisplayName("Should calculate total amount correctly")
    void shouldCalculateTotalAmountCorrectly() {
        List<Order.OrderItem> items = List.of(
                new Order.OrderItem("PROD-001", "Product 1", 2, new BigDecimal("99.99")),
                new Order.OrderItem("PROD-002", "Product 2", 1, new BigDecimal("199.99"))
        );
        Order order = new Order("ORDER-001", "user123", items, Order.OrderStatus.PROCESSING, LocalDateTime.now());

        BigDecimal expected = new BigDecimal("99.99").multiply(BigDecimal.valueOf(2))
                .add(new BigDecimal("199.99"));
        assertEquals(expected, order.getTotalAmount());
    }

    @Test
    @DisplayName("Should handle empty items list")
    void shouldHandleEmptyItemsList() {
        Order order = new Order("ORDER-001", "user123", List.of(), Order.OrderStatus.PROCESSING, LocalDateTime.now());

        assertTrue(order.getItems().isEmpty());
        assertEquals(BigDecimal.ZERO, order.getTotalAmount());
    }

    @Test
    @DisplayName("Should return immutable items list")
    void shouldReturnImmutableItemsList() {
        Order.OrderItem item = new Order.OrderItem("PROD-001", "Product", 2, new BigDecimal("99.99"));
        Order order = new Order("ORDER-001", "user123", List.of(item), Order.OrderStatus.PROCESSING, LocalDateTime.now());

        List<Order.OrderItem> items = order.getItems();
        items.clear();

        assertEquals(1, order.getItems().size());
    }

    @Test
    @DisplayName("Should set and get shipping address")
    void shouldSetAndGetShippingAddress() {
        Order order = new Order("ORDER-001", "user123", List.of(), Order.OrderStatus.PROCESSING, LocalDateTime.now());

        order.setShippingAddress("123 Main St");

        assertEquals("123 Main St", order.getShippingAddress());
    }

    @Test
    @DisplayName("Should set and get tracking number")
    void shouldSetAndGetTrackingNumber() {
        Order order = new Order("ORDER-001", "user123", List.of(), Order.OrderStatus.PROCESSING, LocalDateTime.now());

        order.setTrackingNumber("TRACK-123456");

        assertEquals("TRACK-123456", order.getTrackingNumber());
    }

    @Test
    @DisplayName("Should return correct string representation")
    void shouldReturnCorrectStringRepresentation() {
        Order.OrderItem item = new Order.OrderItem("PROD-001", "Product", 2, new BigDecimal("99.99"));
        Order order = new Order("ORDER-001", "user123", List.of(item), Order.OrderStatus.PROCESSING, LocalDateTime.now());

        String result = order.toString();

        assertTrue(result.contains("ORDER-001"));
        assertTrue(result.contains("user123"));
        assertTrue(result.contains("199.98"));
        assertTrue(result.contains("PROCESSING"));
    }

    @Test
    @DisplayName("OrderItem should calculate total price")
    void orderItemShouldCalculateTotalPrice() {
        Order.OrderItem item = new Order.OrderItem("PROD-001", "Product", 3, new BigDecimal("99.99"));

        assertEquals(new BigDecimal("299.97"), item.getTotalPrice());
    }

    @Test
    @DisplayName("OrderItem should have correct getters")
    void orderItemShouldHaveCorrectGetters() {
        Order.OrderItem item = new Order.OrderItem("PROD-001", "Product", 2, new BigDecimal("99.99"));

        assertEquals("PROD-001", item.getProductId());
        assertEquals("Product", item.getProductName());
        assertEquals(2, item.getQuantity());
        assertEquals(new BigDecimal("99.99"), item.getUnitPrice());
    }

    @Test
    @DisplayName("OrderStatus enum should have all values")
    void orderStatusEnumShouldHaveAllValues() {
        Order.OrderStatus[] statuses = Order.OrderStatus.values();

        assertEquals(6, statuses.length);
        assertTrue(java.util.Arrays.asList(statuses).contains(Order.OrderStatus.PENDING));
        assertTrue(java.util.Arrays.asList(statuses).contains(Order.OrderStatus.PROCESSING));
        assertTrue(java.util.Arrays.asList(statuses).contains(Order.OrderStatus.PAID));
        assertTrue(java.util.Arrays.asList(statuses).contains(Order.OrderStatus.SHIPPED));
        assertTrue(java.util.Arrays.asList(statuses).contains(Order.OrderStatus.DELIVERED));
        assertTrue(java.util.Arrays.asList(statuses).contains(Order.OrderStatus.CANCELLED));
    }

    @Test
    @DisplayName("Should handle zero quantity")
    void shouldHandleZeroQuantity() {
        Order.OrderItem item = new Order.OrderItem("PROD-001", "Product", 0, new BigDecimal("99.99"));

        assertEquals(0, item.getQuantity());
        assertEquals(0, BigDecimal.ZERO.compareTo(item.getTotalPrice()));
    }

    @Test
    @DisplayName("Should handle large quantity")
    void shouldHandleLargeQuantity() {
        Order.OrderItem item = new Order.OrderItem("PROD-001", "Product", 1000, new BigDecimal("99.99"));

        assertEquals(1000, item.getQuantity());
        assertEquals(0, new BigDecimal("99990").compareTo(item.getTotalPrice()));
    }

    @Test
    @DisplayName("Should handle decimal price")
    void shouldHandleDecimalPrice() {
        Order.OrderItem item = new Order.OrderItem("PROD-001", "Product", 1, new BigDecimal("99.99"));

        assertEquals(new BigDecimal("99.99"), item.getTotalPrice());
    }
}