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
package com.alibaba.openagentauth.sample.rs.protocol.rest;

import com.alibaba.openagentauth.mcp.client.McpAuthContext;
import com.alibaba.openagentauth.mcp.client.McpAuthContextHolder;
import com.alibaba.openagentauth.sample.rs.domain.model.Cart;
import com.alibaba.openagentauth.sample.rs.domain.model.Order;
import com.alibaba.openagentauth.sample.rs.domain.model.Product;
import com.alibaba.openagentauth.sample.rs.service.ShoppingService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for ShoppingApiController.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ShoppingApiController Tests")
class ShoppingApiControllerTest {

    @Mock
    private ShoppingService shoppingService;

    private ShoppingApiController controller;

    private MockedStatic<McpAuthContextHolder> mockedAuthContextHolder;
    private MockedStatic<SignedJWT> mockedSignedJwt;

    @BeforeEach
    void setUp() {
        controller = new ShoppingApiController(shoppingService);
        mockedAuthContextHolder = mockStatic(McpAuthContextHolder.class);
    }

    @AfterEach
    void tearDown() {
        if (mockedAuthContextHolder != null) {
            mockedAuthContextHolder.close();
        }
        if (mockedSignedJwt != null) {
            mockedSignedJwt.close();
        }
    }

    private void setupAuthContext(String userId) {
        try {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(userId)
                    .build();
            SignedJWT signedJwt = mock(SignedJWT.class);
            when(signedJwt.getJWTClaimsSet()).thenReturn(claimsSet);

            McpAuthContext authContext = mock(McpAuthContext.class);
            when(authContext.getAgentOaToken()).thenReturn("mock-token-123");
            when(McpAuthContextHolder.getContext()).thenReturn(authContext);

            mockedSignedJwt = mockStatic(SignedJWT.class);
            mockedSignedJwt.when(() -> SignedJWT.parse(anyString())).thenReturn(signedJwt);
        } catch (Exception e) {
            throw new RuntimeException("Failed to setup auth context", e);
        }
    }

    @Test
    @DisplayName("Should search products successfully")
    void shouldSearchProductsSuccessfully() throws Exception {
        List<Product> products = List.of(
                new Product("PROD-001", "Product 1", "Electronics", "Desc 1", new BigDecimal("99.99"), null),
                new Product("PROD-002", "Product 2", "Electronics", "Desc 2", new BigDecimal("199.99"), null)
        );
        when(shoppingService.searchProducts("Electronics", "test", "user123")).thenReturn(products);
        setupAuthContext("user123");

        var response = controller.searchProducts("Electronics", "test");

        assertEquals(200, response.getStatusCodeValue());
        assertEquals(products, response.getBody());
        verify(shoppingService).searchProducts("Electronics", "test", "user123");
    }

    @Test
    @DisplayName("Should search products without keywords")
    void shouldSearchProductsWithoutKeywords() throws Exception {
        List<Product> products = List.of();
        when(shoppingService.searchProducts("Electronics", null, "user123")).thenReturn(products);
        setupAuthContext("user123");

        var response = controller.searchProducts("Electronics", null);

        assertEquals(200, response.getStatusCodeValue());
        assertEquals(products, response.getBody());
    }

    @Test
    @DisplayName("Should return error when search fails")
    void shouldReturnErrorWhenSearchFails() {
        when(shoppingService.searchProducts(anyString(), anyString(), anyString()))
                .thenThrow(new RuntimeException("Database error"));
        setupAuthContext("user123");

        var response = controller.searchProducts("Electronics", "test");

        assertEquals(500, response.getStatusCodeValue());
        assertTrue(response.getBody() instanceof ShoppingApiController.ErrorResponse);
    }

    @Test
    @DisplayName("Should get product by ID successfully")
    void shouldGetProductByIdSuccessfully() throws Exception {
        Product product = new Product("PROD-001", "Product 1", "Electronics", "Desc", new BigDecimal("99.99"), null);
        when(shoppingService.getProduct("PROD-001", "user123")).thenReturn(product);
        setupAuthContext("user123");

        var response = controller.getProduct("PROD-001");

        assertEquals(200, response.getStatusCodeValue());
        assertEquals(product, response.getBody());
    }

    @Test
    @DisplayName("Should return 404 when product not found")
    void shouldReturn404WhenProductNotFound() throws Exception {
        when(shoppingService.getProduct("INVALID-ID", "user123")).thenReturn(null);
        setupAuthContext("user123");

        var response = controller.getProduct("INVALID-ID");

        assertEquals(404, response.getStatusCodeValue());
        assertTrue(response.getBody() instanceof ShoppingApiController.ErrorResponse);
    }

    @Test
    @DisplayName("Should add product to cart successfully")
    void shouldAddProductToCartSuccessfully() throws Exception {
        when(shoppingService.addToCart("PROD-001", 2, "user123"))
                .thenReturn("Successfully added 2 units");
        setupAuthContext("user123");

        ShoppingApiController.AddToCartRequest request = new ShoppingApiController.AddToCartRequest();
        request.setProductId("PROD-001");
        request.setQuantity(2);

        var response = controller.addToCart(request);

        assertEquals(200, response.getStatusCodeValue());
        assertTrue(response.getBody() instanceof ShoppingApiController.SuccessResponse);
        verify(shoppingService).addToCart("PROD-001", 2, "user123");
    }

    @Test
    @DisplayName("Should return 400 when adding to cart with invalid request")
    void shouldReturn400WhenAddingToCartWithInvalidRequest() throws Exception {
        when(shoppingService.addToCart(anyString(), anyInt(), anyString()))
                .thenThrow(new IllegalArgumentException("Invalid quantity"));
        setupAuthContext("user123");

        ShoppingApiController.AddToCartRequest request = new ShoppingApiController.AddToCartRequest();
        request.setProductId("PROD-001");
        request.setQuantity(-1);

        var response = controller.addToCart(request);

        assertEquals(400, response.getStatusCodeValue());
        assertTrue(response.getBody() instanceof ShoppingApiController.ErrorResponse);
    }

    @Test
    @DisplayName("Should get user cart successfully")
    void shouldGetUserCartSuccessfully() throws Exception {
        Cart cart = new Cart("user123");
        when(shoppingService.getCart("user123")).thenReturn(cart);
        setupAuthContext("user123");

        var response = controller.getCart();

        assertEquals(200, response.getStatusCodeValue());
        assertEquals(cart, response.getBody());
    }

    @Test
    @DisplayName("Should purchase product successfully")
    void shouldPurchaseProductSuccessfully() throws Exception {
        Order order = new Order(
                "ORDER-001",
                "user123",
                List.of(new Order.OrderItem("PROD-001", "Product", 1, new BigDecimal("99.99"))),
                Order.OrderStatus.PROCESSING,
                java.time.LocalDateTime.now()
        );
        when(shoppingService.purchaseProduct("PROD-001", 1, "user123")).thenReturn(order);
        setupAuthContext("user123");

        ShoppingApiController.PurchaseRequest request = new ShoppingApiController.PurchaseRequest();
        request.setProductId("PROD-001");
        request.setQuantity(1);

        var response = controller.purchaseProduct(request);

        assertEquals(200, response.getStatusCodeValue());
        assertEquals(order, response.getBody());
    }

    @Test
    @DisplayName("Should query order successfully")
    void shouldQueryOrderSuccessfully() throws Exception {
        Order order = new Order(
                "ORDER-001",
                "user123",
                List.of(),
                Order.OrderStatus.PROCESSING,
                java.time.LocalDateTime.now()
        );
        when(shoppingService.queryOrder("ORDER-001", "user123")).thenReturn(order);
        setupAuthContext("user123");

        var response = controller.queryOrder("ORDER-001");

        assertEquals(200, response.getStatusCodeValue());
        assertEquals(order, response.getBody());
    }

    @Test
    @DisplayName("Should return 404 when order not found")
    void shouldReturn404WhenOrderNotFound() throws Exception {
        when(shoppingService.queryOrder("INVALID-ORDER", "user123")).thenReturn(null);
        setupAuthContext("user123");

        var response = controller.queryOrder("INVALID-ORDER");

        assertEquals(404, response.getStatusCodeValue());
        assertTrue(response.getBody() instanceof ShoppingApiController.ErrorResponse);
    }

    @Test
    @DisplayName("Should list orders successfully")
    void shouldListOrdersSuccessfully() throws Exception {
        List<Order> orders = List.of(
                new Order("ORDER-001", "user123", List.of(), Order.OrderStatus.PROCESSING, java.time.LocalDateTime.now())
        );
        when(shoppingService.listOrders("user123")).thenReturn(orders);
        setupAuthContext("user123");

        var response = controller.listOrders();

        assertEquals(200, response.getStatusCodeValue());
        assertEquals(orders, response.getBody());
    }

    @Test
    @DisplayName("AddToCartRequest should set and get fields")
    void addToCartRequestShouldSetAndGetFields() {
        ShoppingApiController.AddToCartRequest request = new ShoppingApiController.AddToCartRequest();
        request.setProductId("PROD-001");
        request.setQuantity(5);

        assertEquals("PROD-001", request.getProductId());
        assertEquals(5, request.getQuantity());
    }

    @Test
    @DisplayName("PurchaseRequest should set and get fields")
    void purchaseRequestShouldSetAndGetFields() {
        ShoppingApiController.PurchaseRequest request = new ShoppingApiController.PurchaseRequest();
        request.setProductId("PROD-001");
        request.setQuantity(3);

        assertEquals("PROD-001", request.getProductId());
        assertEquals(3, request.getQuantity());
    }

    @Test
    @DisplayName("SuccessResponse should set and get message")
    void successResponseShouldSetAndGetMessage() {
        ShoppingApiController.SuccessResponse response = new ShoppingApiController.SuccessResponse("Success");

        assertEquals("Success", response.getMessage());
    }

    @Test
    @DisplayName("ErrorResponse should set and get error")
    void errorResponseShouldSetAndGetError() {
        ShoppingApiController.ErrorResponse response = new ShoppingApiController.ErrorResponse("Error occurred");

        assertEquals("Error occurred", response.getError());
    }
}