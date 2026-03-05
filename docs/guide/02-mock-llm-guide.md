# Mock LLM Reference Guide

This guide explains how the Mock LLM works in the sample project and provides a reference for available products and matching rules.

## Overview

The Mock LLM is a simplified implementation designed for quick testing and demonstration purposes. It simulates AI agent behavior by extracting keywords from user requests and matching them against available products in the in-memory shopping repository.

## How Mock LLM Works

### Configuration

The Mock LLM behavior is configured in `sample-agent/src/main/resources/application.yml` under the `agent.mock.strategies` section:

```yaml
agent:
  mock:
    enabled: false  # Enable when using --profile mock-llm
    strategies:
      - name: shopping-search
        intent: "search products"
        keywords: [ "search", "find", "look for", "show" ]
        tool-server: "shopping"
        tool-name: "search_products"
        param-rules:
          - param: "keywords"
            source: "user_input"
            pattern: "search\\s+(.+)"
        response-template: "Found the following products: {result}"
        error-template: "Search failed: {error}"
```

### Matching Algorithm

The Mock LLM uses a strategy-based matching algorithm:

1. **Keyword Matching**: Each strategy has a list of keywords. The user input is split into words and matched against these keywords.
2. **Strategy Selection**: If any keyword from a strategy matches the user input, that strategy is selected.
3. **Parameter Extraction**: The selected strategy uses regex patterns to extract parameters from the user input.
4. **Tool Invocation**: The extracted parameters are passed to the configured tool server and tool name.
5. **Response Formatting**: The result is formatted using the response template.

### Matching Rules

- **Keyword-Based**: Matching is based on predefined keywords in each strategy
- **Case-Insensitive**: Keyword matching is case-insensitive
- **Priority**: Strategies are evaluated in order; first match wins
- **Default Strategy**: If no strategy matches, the "default" strategy is used

### Available Strategies

#### 1. Shopping Search
- **Intent**: Search for products
- **Keywords**: `search`, `find`, `look for`, `show`
- **Tool**: `shopping.search_products`
- **Parameter**: Extracts keywords from user input using pattern `search\s+(.+)`
- **Example**: "search smartphone" → searches for products matching "smartphone"

#### 2. Shopping Purchase
- **Intent**: Purchase products
- **Keywords**: `purchase`, `buy`, `order`
- **Tool**: `shopping.purchase_product`
- **Parameters**: 
  - `productId`: Extracted using pattern `purchase\s+(\w+)`
  - `quantity`: Defaults to "1"
- **Example**: "purchase PROD-005" → purchases product with ID PROD-005

#### 3. Greeting
- **Intent**: Greet the user
- **Keywords**: `hello`, `hi`, `hey`
- **Tool**: None (no-tool: true)
- **Response**: Fixed greeting message

#### 4. Default
- **Intent**: Handle unrecognized requests
- **Keywords**: None (catch-all)
- **Tool**: None (no-tool: true)
- **Response**: Error message asking user to try again

### Matching Algorithm

The Mock LLM uses a word-based matching algorithm:

1. **Keyword Extraction**: Extracts keywords from the user's natural language request
2. **Product Search**: Searches for products where ANY keyword matches the product name or description
3. **Category Filter**: Optionally filters by product category

### Matching Rules

- **Case-Insensitive**: Matching is case-insensitive (e.g., "phone" matches "Smartphone")
- **Partial Match**: Keywords can match partial words (e.g., "phone" matches "Smartphone")
- **Any Keyword Match**: If multiple keywords are provided, a product matches if ANY keyword matches
- **Name & Description**: Matching is performed against both product name and description

### Example

**User Request**: "I want to buy a smartphone"

**Keywords Extracted**: `["want", "buy", "smartphone"]`

**Matching Products**: 
- ✅ "Smartphone X" (matches "smartphone")
- ✅ "Laptop Pro" (no match)
- ✅ "Wireless Headphones" (no match)

## Available Products

The sample project includes 12 default products across 3 categories:

### Clothing (4 products)

| ID | Name | Description | Price |
|----|------|-------------|-------|
| PROD-001 | Down Jacket A | Excellent warmth, suitable for daily commute | ¥599.00 |
| PROD-002 | Wool Coat B | Fashionable and versatile, suitable for business | ¥899.00 |
| PROD-003 | Cotton Jacket C | Lightweight and comfortable, suitable for casual wear | ¥399.00 |
| PROD-004 | Wool Sweater D | Soft and comfortable, warm and breathable | ¥299.00 |

### Electronics (4 products)

| ID | Name | Description | Price |
|----|------|-------------|-------|
| PROD-005 | Smartphone X | Latest model with advanced features | ¥4,999.00 |
| PROD-006 | Laptop Pro | High performance for professionals | ¥8,999.00 |
| PROD-007 | Wireless Headphones | Noise cancelling, premium sound | ¥1,299.00 |
| PROD-008 | Smart Watch | Fitness tracking and notifications | ¥1,999.00 |

### Books (4 products)

| ID | Name | Description | Price |
|----|------|-------------|-------|
| PROD-009 | Java Programming Guide | Comprehensive Java tutorial | ¥89.00 |
| PROD-010 | Design Patterns | Classic software design patterns | ¥79.00 |
| PROD-011 | Clean Code | Writing maintainable code | ¥69.00 |
| PROD-012 | System Design Interview | System design preparation | ¥99.00 |

## Sample Queries

Here are some example queries and their expected results based on the configured strategies:

| Query | Matched Strategy | Keywords Matched | Expected Result |
|-------|------------------|------------------|-----------------|
| "search smartphone" | shopping-search | search | Searches for products matching "smartphone" |
| "find laptop" | shopping-search | find | Searches for products matching "laptop" |
| "show me books" | shopping-search | show | Searches for products matching "books" |
| "purchase PROD-005" | shopping-purchase | purchase | Purchases product with ID PROD-005 |
| "buy PROD-001" | shopping-purchase | buy | Purchases product with ID PROD-001 |
| "hello" | greeting | hello | Returns greeting message |
| "hi there" | greeting | hi | Returns greeting message |
| "random text" | default | none | Returns error message |

## Tips for Testing

1. **Use Strategy Keywords**: Start your query with one of the strategy keywords (search, find, show, purchase, buy, order)
2. **For Search**: Use "search [keyword]" or "find [keyword]" to search for products
3. **For Purchase**: Use "purchase [productId]" or "buy [productId]" to purchase a specific product
4. **Product IDs**: Use the product IDs from the table above (PROD-001 to PROD-012) for purchases
5. **Try Greetings**: Use "hello", "hi", or "hey" to test the greeting strategy

## Limitations

- **No Real AI**: Mock LLM does not use actual AI models
- **Simple Matching**: Uses basic keyword matching, not semantic understanding
- **Fixed Dataset**: Only searches the predefined 12 products
- **No Context**: Does not maintain conversation context

## For Real AI Experience

To use a real AI model for more natural interactions, see [Using QwenCode](01-quick-start.md#optional-use-qwencode-for-deeper-experience) in the Quick Start Guide.

---

**Document Version**: 1.0.0  
**Last Updated**: 2026-02-13  
**Maintainer**: Open Agent Auth Team
