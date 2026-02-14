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
package com.alibaba.openagentauth.sample.rs.service;

import com.alibaba.openagentauth.sample.rs.domain.model.Cart;
import com.alibaba.openagentauth.sample.rs.domain.model.Order;
import com.alibaba.openagentauth.sample.rs.domain.model.Product;
import com.alibaba.openagentauth.sample.rs.domain.repository.InMemoryShoppingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for ShoppingService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ShoppingService Tests")
class ShoppingServiceTest {

    @Mock
    private InMemoryShoppingRepository repository;

    private ShoppingService shoppingService;

    private Product testProduct;

    @BeforeEach
    void setUp() {
        shoppingService = new ShoppingService(repository);
        testProduct = new Product(
                "PROD-001",
                "Test Product",
                "Electronics",
                "A test product",
                new BigDecimal("99.99"),
                "https://example.com/image.jpg"
        );
    }

    @Test
    @DisplayName("Should search products by category and keywords")
    void shouldSearchProductsByCategoryAndKeywords() {
        List<Product> expectedProducts = List.of(testProduct);
        when(repository.searchProducts("Electronics", "test")).thenReturn(expectedProducts);

        List<Product> result = shoppingService.searchProducts("Electronics", "test", "user123");

        assertEquals(expectedProducts, result);
        verify(repository).searchProducts("Electronics", "test");
    }

    @Test
    @DisplayName("Should search products by category only")
    void shouldSearchProductsByCategoryOnly() {
        List<Product> expectedProducts = List.of(testProduct);
        when(repository.searchProducts("Electronics", null)).thenReturn(expectedProducts);

        List<Product> result = shoppingService.searchProducts("Electronics", null, "user123");

        assertEquals(expectedProducts, result);
        verify(repository).searchProducts("Electronics", null);
    }

    @Test
    @DisplayName("Should get product by ID")
    void shouldGetProductById() {
        when(repository.getProduct("PROD-001")).thenReturn(testProduct);

        Product result = shoppingService.getProduct("PROD-001", "user123");

        assertEquals(testProduct, result);
        verify(repository).getProduct("PROD-001");
    }

    @Test
    @DisplayName("Should return null when product not found")
    void shouldReturnNullWhenProductNotFound() {
        when(repository.getProduct("INVALID-ID")).thenReturn(null);

        Product result = shoppingService.getProduct("INVALID-ID", "user123");

        assertNull(result);
    }

    @Test
    @DisplayName("Should add product to cart successfully")
    void shouldAddProductToCartSuccessfully() {
        Cart cart = new Cart("user123");
        when(repository.getProduct("PROD-001")).thenReturn(testProduct);
        when(repository.getOrCreateCart("user123")).thenReturn(cart);
        doNothing().when(repository).saveCart(any(Cart.class));

        String result = shoppingService.addToCart("PROD-001", 2, "user123");

        assertTrue(result.contains("Successfully added"));
        assertTrue(result.contains("2"));
        assertTrue(result.contains("PROD-001"));
        verify(repository).getProduct("PROD-001");
        verify(repository).getOrCreateCart("user123");
        verify(repository).saveCart(any(Cart.class));
    }

    @Test
    @DisplayName("Should throw exception when adding non-existent product to cart")
    void shouldThrowExceptionWhenAddingNonExistentProductToCart() {
        when(repository.getProduct("INVALID-ID")).thenReturn(null);

        assertThrows(IllegalArgumentException.class, () -> {
            shoppingService.addToCart("INVALID-ID", 1, "user123");
        });
    }

    @Test
    @DisplayName("Should throw exception when adding zero quantity to cart")
    void shouldThrowExceptionWhenAddingZeroQuantityToCart() {
        when(repository.getProduct("PROD-001")).thenReturn(testProduct);

        assertThrows(IllegalArgumentException.class, () -> {
            shoppingService.addToCart("PROD-001", 0, "user123");
        });
    }

    @Test
    @DisplayName("Should throw exception when adding negative quantity to cart")
    void shouldThrowExceptionWhenAddingNegativeQuantityToCart() {
        when(repository.getProduct("PROD-001")).thenReturn(testProduct);

        assertThrows(IllegalArgumentException.class, () -> {
            shoppingService.addToCart("PROD-001", -1, "user123");
        });
    }

    @Test
    @DisplayName("Should get user cart")
    void shouldGetUserCart() {
        Cart expectedCart = new Cart("user123");
        when(repository.getOrCreateCart("user123")).thenReturn(expectedCart);

        Cart result = shoppingService.getCart("user123");

        assertEquals(expectedCart, result);
        verify(repository).getOrCreateCart("user123");
    }

    @Test
    @DisplayName("Should purchase product successfully")
    void shouldPurchaseProductSuccessfully() {
        when(repository.getProduct("PROD-001")).thenReturn(testProduct);
        doNothing().when(repository).saveOrder(any(Order.class));

        Order result = shoppingService.purchaseProduct("PROD-001", 1, "user123");

        assertNotNull(result);
        assertEquals("user123", result.getUserId());
        assertEquals(Order.OrderStatus.PROCESSING, result.getStatus());
        assertEquals(1, result.getItems().size());
        assertEquals("PROD-001", result.getItems().get(0).getProductId());
        assertEquals(new BigDecimal("99.99"), result.getTotalAmount());
        verify(repository).getProduct("PROD-001");
        verify(repository).saveOrder(any(Order.class));
    }

    @Test
    @DisplayName("Should throw exception when purchasing non-existent product")
    void shouldThrowExceptionWhenPurchasingNonExistentProduct() {
        when(repository.getProduct("INVALID-ID")).thenReturn(null);

        assertThrows(IllegalArgumentException.class, () -> {
            shoppingService.purchaseProduct("INVALID-ID", 1, "user123");
        });
    }

    @Test
    @DisplayName("Should throw exception when purchasing with zero quantity")
    void shouldThrowExceptionWhenPurchasingWithZeroQuantity() {
        when(repository.getProduct("PROD-001")).thenReturn(testProduct);

        assertThrows(IllegalArgumentException.class, () -> {
            shoppingService.purchaseProduct("PROD-001", 0, "user123");
        });
    }

    @Test
    @DisplayName("Should query order by ID")
    void shouldQueryOrderById() {
        Order order = new Order(
                "ORDER-001",
                "user123",
                List.of(new Order.OrderItem("PROD-001", "Test Product", 1, new BigDecimal("99.99"))),
                Order.OrderStatus.PROCESSING,
                java.time.LocalDateTime.now()
        );
        when(repository.getOrder("ORDER-001")).thenReturn(order);

        Order result = shoppingService.queryOrder("ORDER-001", "user123");

        assertEquals(order, result);
        verify(repository).getOrder("ORDER-001");
    }

    @Test
    @DisplayName("Should return null when querying order of different user")
    void shouldReturnNullWhenQueryingOrderOfDifferentUser() {
        Order order = new Order(
                "ORDER-001",
                "user456",
                List.of(new Order.OrderItem("PROD-001", "Test Product", 1, new BigDecimal("99.99"))),
                Order.OrderStatus.PROCESSING,
                java.time.LocalDateTime.now()
        );
        when(repository.getOrder("ORDER-001")).thenReturn(order);

        Order result = shoppingService.queryOrder("ORDER-001", "user123");

        assertNull(result);
    }

    @Test
    @DisplayName("Should return null when querying non-existent order")
    void shouldReturnNullWhenQueryingNonExistentOrder() {
        when(repository.getOrder("INVALID-ORDER")).thenReturn(null);

        Order result = shoppingService.queryOrder("INVALID-ORDER", "user123");

        assertNull(result);
    }

    @Test
    @DisplayName("Should list orders for user")
    void shouldListOrdersForUser() {
        List<Order> expectedOrders = List.of(
                new Order("ORDER-001", "user123", List.of(), Order.OrderStatus.PROCESSING, java.time.LocalDateTime.now()),
                new Order("ORDER-002", "user123", List.of(), Order.OrderStatus.PAID, java.time.LocalDateTime.now())
        );
        when(repository.getOrdersByUserId("user123")).thenReturn(expectedOrders);

        List<Order> result = shoppingService.listOrders("user123");

        assertEquals(expectedOrders, result);
        verify(repository).getOrdersByUserId("user123");
    }

    @Test
    @DisplayName("Should calculate correct total amount for multiple items")
    void shouldCalculateCorrectTotalAmountForMultipleItems() {
        when(repository.getProduct("PROD-001")).thenReturn(testProduct);
        doNothing().when(repository).saveOrder(any(Order.class));

        Order result = shoppingService.purchaseProduct("PROD-001", 3, "user123");

        assertEquals(new BigDecimal("299.97"), result.getTotalAmount());
    }
}