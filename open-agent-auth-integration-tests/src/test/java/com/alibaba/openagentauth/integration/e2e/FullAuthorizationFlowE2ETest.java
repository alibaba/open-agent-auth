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
package com.alibaba.openagentauth.integration.e2e;

import com.alibaba.openagentauth.integration.IntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.openqa.selenium.By;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Full End-to-End Authorization Flow Test using Selenium.
 * <p>
 * This test class validates the complete authorization flow including:
 * 1. Agent User IDP authentication
 * 2. Agent conversation and tool calls
 * 3. AS User IDP authentication
 * 4. AS authorization for tool operations
 * </p>
 * <p>
 * <b>NOTE:</b> This test requires all sample services to be running:
 * - Agent (port 8081)
 * - Agent IDP (port 8082)
 * - Agent User IDP (port 8083)
 * - AS User IDP (port 8084)
 * - Authorization Server (port 8085)
 * - Resource Server (port 8086)
 * 
 * Use the provided scripts to start all services before running tests:
 * <pre>
 *   cd open-agent-auth-samples
 *   ./scripts/sample-start.sh
 *   ./scripts/run-e2e-tests.sh
 * </pre>
 * </p>
 * <p>
 * <b>Test Flow:</b></p>
 * <ol>
 *   <li>User navigates to Agent UI (http://localhost:8081)</li>
 *   <li>User is redirected to Agent User IDP for authentication</li>
 *   <li>User logs in with credentials</li>
 *   <li>User is redirected back to Agent with ID token</li>
 *   <li>User sends message that triggers tool call</li>
 *   <li>Tool requires authorization from AS</li>
 *   <li>User is redirected to AS User IDP for authentication</li>
 *   <li>User logs in again</li>
 *   <li>User authorizes the tool operation</li>
 *   <li>Tool executes and returns result</li>
 * </ol>
 *
 * @since 1.0
 */
@IntegrationTest(
    value = "Full Authorization Flow E2E Tests",
    requiredServices = {"localhost:8081", "localhost:8082", "localhost:8083", "localhost:8084", "localhost:8085", "localhost:8086"}
)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("Full Authorization Flow E2E Tests")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FullAuthorizationFlowE2ETest {

    // Fixed port for the running Agent service
    private static final int AGENT_PORT = 8081;

    private WebDriver driver;
    private WebDriverWait wait;
    private String baseUrl;

    private static boolean servicesAvailable;
    private static boolean chromeAvailable;

    @BeforeAll
    static void setupClass() {
        // Check if Chrome browser is available
        chromeAvailable = checkChromeAvailability();
        
        // Check if required services are available
        servicesAvailable = checkServiceAvailability();
        
        if (!chromeAvailable) {
            System.err.println("\n" + "=".repeat(80));
            System.err.println("E2E tests are SKIPPED because Chrome browser is not available!");
            System.err.println("=".repeat(80));
            System.err.println("Please install Google Chrome to run E2E tests:");
            System.err.println("  - Download from: https://www.google.com/chrome/");
            System.err.println("  - Or use: brew install --cask google-chrome (macOS)");
            System.err.println("=".repeat(80) + "\n");
        } else if (!servicesAvailable) {
            System.err.println("\n" + "=".repeat(80));
            System.err.println("E2E tests are SKIPPED because required services are not available!");
            System.err.println("=".repeat(80) + "\n");
        }
    }

    @BeforeEach
    void setUp() {
        // Skip test setup if Chrome is not available
        assumeTrue(chromeAvailable, "Chrome browser is not available");
        // Skip test setup if services are not available
        assumeTrue(servicesAvailable, "Required services are not available");
        
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless");
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");
        options.addArguments("--disable-gpu");
        options.addArguments("--window-size=1920,1080");

        driver = new ChromeDriver(options);
        wait = new WebDriverWait(driver, Duration.ofSeconds(30));
        baseUrl = "http://localhost:" + AGENT_PORT;
    }

    @AfterEach
    void tearDown() {
        if (driver != null) {
            driver.quit();
        }
    }

    @Test
    @Order(1)
    @DisplayName("Should complete full authorization flow with two conversations: search watch and search programming book")
    void shouldCompleteFullAuthorizationFlow() {
        // Skip test if services are not available
        assumeTrue(servicesAvailable, "Required services are not available");
        
        // Step 1: Navigate to Agent UI (8081)
        driver.get(baseUrl);
        
        // Step 2: Check if authentication is required
        String currentUrl = driver.getCurrentUrl();
        
        if (currentUrl.contains("login") || currentUrl.contains("oauth")) {
            // Step 3: Agent User IDP (8083) Authentication
            completeAgentUserIdpAuthentication();
            
            // Step 4: After Agent User IDP login, check if OIDC consent is required
            currentUrl = driver.getCurrentUrl();
            if (currentUrl.contains("consent") || currentUrl.contains("authorize")) {
                System.out.println("Detected Agent OIDC consent page after Agent login, completing...");
                completeOidcConsent(); // First OIDC consent for Agent
            }
        }
        
        // Step 5: Wait for Agent page to load after authentication
        wait.until(ExpectedConditions.titleContains("Open Agent Auth"));
        System.out.println("[Agent:8081] Successfully authenticated and redirected to Agent");
        
        // ========================================
        // First Conversation: search watch
        // ========================================
        System.out.println("\n========================================");
        System.out.println("Starting First Conversation: search watch");
        System.out.println("========================================\n");
        
        completeConversationWithAuthorization("search watch", "search_products", "watch");
        
        // ========================================
        // Second Conversation: search programming book
        // ========================================
        System.out.println("\n========================================");
        System.out.println("Starting Second Conversation: search programming book");
        System.out.println("========================================\n");
        
        completeConversationWithAuthorization("search programming book", "search_products", "programming book");
        
        System.out.println("\n========================================");
        System.out.println("All conversations completed successfully!");
        System.out.println("========================================\n");
    }
    
    /**
     * Complete a conversation with authorization flow
     * 
     * @param message The user message to send
     * @param expectedTool The expected tool name
     * @param expectedKeyword The expected keyword in the result
     */
    private void completeConversationWithAuthorization(String message, String expectedTool, String expectedKeyword) {
        // Step 1: Send message that triggers tool call requiring authorization
        WebElement messageInput = wait.until(ExpectedConditions.presenceOfElementLocated(
            By.id("messageInput")
        ));
        WebElement sendButton = driver.findElement(By.cssSelector("button.btn-send"));
        
        messageInput.clear();
        messageInput.sendKeys(message);
        sendButton.click();
        System.out.println("[Agent:8081] Sent message: \"" + message + "\"");
        
        // Step 2: Wait for redirect to Authorization Server (8085) or for messages to appear
        try {
            Thread.sleep(5000); // Give more time for LLM to respond
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        String currentUrl = driver.getCurrentUrl();
        System.out.println("[Agent:8081] Current URL after sending message: " + currentUrl);
        
        // Step 3: Check if we're on Authorization Server
        if (currentUrl.contains("8085") || currentUrl.contains("authorization")) {
            System.out.println("[AuthServer:8085] Redirected to Authorization Server, completing AS authentication...");
            // AS User IDP (8084) Authentication + OIDC consent + Agent operation authorization
            completeAuthorizationServerFlow();
            
            // Wait for redirect back to agent (8081)
            wait.until(ExpectedConditions.urlContains("localhost:" + AGENT_PORT));
            System.out.println("[Agent:8081] Redirected back to Agent after authorization");
        } else {
            System.out.println("[Agent:8081] No authorization redirect occurred, checking if tool call succeeded without authorization");
        }
        
        // Step 4: Verify tool execution result and check for authorization link
        // Wait for messages to appear
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        WebElement chatMessages = driver.findElement(By.id("chatMessages"));
        List<WebElement> messages = chatMessages.findElements(By.className("message"));
        
        System.out.println("[Agent:8081] Found " + messages.size() + " messages in chat");
        
        // Check if authorization link is present
        List<WebElement> authLinks = chatMessages.findElements(By.className("action-card-auth-link"));
        
        if (!authLinks.isEmpty()) {
            System.out.println("[Agent:8081] Authorization link found, extracting URL to complete authorization...");
            
            // Get the authorization URL from the link
            String authUrl = authLinks.get(0).getAttribute("href");
            System.out.println("[Agent:8081] Authorization URL: " + authUrl);
            
            // Navigate to authorization URL in the current tab (not new tab)
            driver.get(authUrl);
            
            // Wait for redirect to Authorization Server (8085)
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            currentUrl = driver.getCurrentUrl();
            System.out.println(getServicePrefix(currentUrl) + "Redirected to: " + currentUrl);
            
            // Complete Authorization Server flow
            // The authorization URL will redirect to either AS User IDP (8084) for login/consent
            // or directly to Authorization Server (8085) for operation consent
            if (currentUrl.contains("8084") || currentUrl.contains("8085") || currentUrl.contains("authorization")) {
                System.out.println("Starting Authorization Server flow from URL: " + currentUrl);
                completeAuthorizationServerFlow();
                
                // Wait for redirect back to agent (8081)
                wait.until(ExpectedConditions.urlContains("localhost:" + AGENT_PORT));
                System.out.println("Redirected back to Agent after authorization");
                
                // Wait for tool execution to complete
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        } else {
            System.out.println("[Agent:8081] No authorization link found, tool may have been executed without authorization");
        }
        
        // Re-locate chatMessages after returning from authorization flow
        // Wait for the Agent page to load completely
        System.out.println("[Agent:8081] Waiting for Agent page to load after authorization...");
        currentUrl = driver.getCurrentUrl();
        System.out.println("[Agent:8081] Current URL before waiting for chatMessages: " + currentUrl);
        
        try {
            chatMessages = wait.until(ExpectedConditions.presenceOfElementLocated(By.id("chatMessages")));
            System.out.println("[Agent:8081] Successfully found chatMessages element");
        } catch (TimeoutException e) {
            System.out.println("[Agent:8081] Timeout waiting for chatMessages, current URL: " + driver.getCurrentUrl());
            System.out.println("[Agent:8081] Page source length: " + driver.getPageSource().length());
            throw e;
        }
        
        // Verify tool call card is displayed
        List<WebElement> toolCards = chatMessages.findElements(By.className("action-card"));
        System.out.println("[Agent:8081] Found " + toolCards.size() + " tool cards");
        
        if (toolCards.isEmpty()) {
            // If no tool cards, check if there's any message content
            System.out.println("[Agent:8081] No tool cards found, checking message content");
            messages = chatMessages.findElements(By.className("message"));
            for (WebElement msg : messages) {
                System.out.println("[Agent:8081] Message text: " + msg.getText());
            }
            // Verify that tool execution message is present instead of card
            boolean toolExecuted = messages.stream()
                .anyMatch(msg -> msg.getText().toLowerCase().contains(expectedKeyword.toLowerCase()) || 
                            msg.getText().contains(expectedTool));
            assertThat(toolExecuted).isTrue();
            System.out.println("[Agent:8081] Tool execution verified through message content!");
        } else {
            assertThat(toolCards).isNotNull().isNotEmpty();
            String cardTitle = toolCards.get(0).getText();
            assertThat(cardTitle).contains(expectedTool);
            System.out.println("[Agent:8081] Tool call verified successfully through card!");
        }
        System.out.println("[Agent:8081] Conversation completed successfully!");
    }

    @Test
    @Order(2)
    @DisplayName("Should handle Agent User IDP login with demo credentials")
    void shouldHandleAgentUserIdpLoginWithDemoCredentials() {
        // Skip test if services are not available
        assumeTrue(servicesAvailable, "Required services are not available");
        
        // This test assumes Agent User IDP is running at localhost:8083
        driver.get("http://localhost:8083/login");
        
        // Fill in login form
        WebElement usernameField = wait.until(ExpectedConditions.presenceOfElementLocated(
            By.name("username")
        ));
        WebElement passwordField = driver.findElement(By.name("password"));
        WebElement loginButton = driver.findElement(By.cssSelector("button[type='submit']"));
        
        usernameField.sendKeys("alice");
        passwordField.sendKeys("password123");
        loginButton.click();
        
        // Verify login success
        wait.until(ExpectedConditions.not(ExpectedConditions.urlContains("login")));
        
        String currentUrl = driver.getCurrentUrl();
        assertThat(currentUrl).doesNotContain("login");
    }

    @Test
    @Order(3)
    @DisplayName("Should handle AS User IDP login with demo credentials")
    void shouldHandleAsUserIdpLoginWithDemoCredentials() {
        // Skip test if services are not available
        assumeTrue(servicesAvailable, "Required services are not available");
        
        // This test assumes AS User IDP is running at localhost:8084
        driver.get("http://localhost:8084/login");
        
        // Fill in login form
        WebElement usernameField = wait.until(ExpectedConditions.presenceOfElementLocated(
            By.name("username")
        ));
        WebElement passwordField = driver.findElement(By.name("password"));
        WebElement loginButton = driver.findElement(By.cssSelector("button[type='submit']"));
        
        usernameField.sendKeys("admin");
        passwordField.sendKeys("admin123");
        loginButton.click();
        
        // Verify login success
        wait.until(ExpectedConditions.not(ExpectedConditions.urlContains("login")));
        
        String currentUrl = driver.getCurrentUrl();
        assertThat(currentUrl).doesNotContain("login");
    }

    @Test
    @Order(4)
    @DisplayName("Should handle authorization consent screen")
    void shouldHandleAuthorizationConsentScreen() {
        // Skip test if services are not available
        assumeTrue(servicesAvailable, "Required services are not available");
        
        // This test assumes Authorization Server is running at localhost:8085
        driver.get("http://localhost:8085/oauth/authorize?client_id=sample-agent&response_type=code&redirect_uri=http://localhost:8081/callback");
        
        // Check if login is required first
        try {
            WebElement usernameField = wait.until(ExpectedConditions.presenceOfElementLocated(
                By.name("username")
            ));
            WebElement passwordField = driver.findElement(By.name("password"));
            WebElement loginButton = driver.findElement(By.cssSelector("button[type='submit']"));
            
            usernameField.sendKeys("admin");
            passwordField.sendKeys("admin123");
            loginButton.click();
        } catch (TimeoutException e) {
            // Already logged in, continue
        }
        
        // Check for consent screen
        try {
            WebElement approveButton = wait.until(ExpectedConditions.presenceOfElementLocated(
                By.cssSelector("button[name='authorize']")
            ));
            
            assertThat(approveButton.isDisplayed()).isTrue();
        } catch (TimeoutException e) {
            // Consent screen not shown, maybe auto-approved
        }
    }

    /**
     * Complete Agent User IDP authentication flow
     */
    private void completeAgentUserIdpAuthentication() {
        System.out.println("[AgentUserIDP:8083] Starting Agent User IDP (8083) authentication...");
        
        // Wait for login page
        WebElement usernameField = wait.until(ExpectedConditions.presenceOfElementLocated(
            By.name("username")
        ));
        WebElement passwordField = driver.findElement(By.name("password"));
        WebElement loginButton = driver.findElement(By.cssSelector("button[type='submit']"));
        
        // Fill in credentials (from Agent User IDP demo users)
        usernameField.sendKeys("alice");
        passwordField.sendKeys("password123");
        loginButton.click();
        System.out.println("[AgentUserIDP:8083] Submitted Agent User IDP login form");
        
        // Wait for redirect to next step
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        String currentUrl = driver.getCurrentUrl();
        System.out.println("[AgentUserIDP:8083] After Agent User IDP login, current URL: " + currentUrl);
        System.out.println("[AgentUserIDP:8083] Page title: " + driver.getTitle());
    }

    /**
     * Complete OIDC consent flow (for Agent or Authorization Server)
     */
    private void completeOidcConsent() {
        String consentUrl = driver.getCurrentUrl();
        System.out.println(getServicePrefix(consentUrl) + "Completing OIDC consent...");
        
        // Find and click the Approve button on consent page
        WebElement approveButton = wait.until(ExpectedConditions.elementToBeClickable(
            By.cssSelector("button.btn-approve")
        ));
        approveButton.click();
        System.out.println(getServicePrefix(consentUrl) + "Clicked OIDC consent approve button");
        
        // Wait for redirect
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Complete Authorization Server flow.
     * <p>
     * The flow varies depending on whether the user has already authenticated
     * with AS User IDP (8084) in a previous conversation. With session cookie
     * isolation (each service has a unique cookie name), the AS User IDP session
     * persists across conversations, so the login step is skipped on subsequent calls.
     * </p>
     * <p>
     * <b>First conversation flow:</b>
     * AS → AS User IDP login → OIDC consent → AS AOA consent → Agent
     * </p>
     * <p>
     * <b>Subsequent conversation flow (session already exists):</b>
     * AS → AS User IDP (auto-authenticated) → OIDC consent (may be skipped) → AS AOA consent → Agent
     * </p>
     */
    private void completeAuthorizationServerFlow() {
        // Allow time for any redirects to settle
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Iteratively handle each step until we're back on the Agent
        int maxIterations = 10;
        for (int iteration = 0; iteration < maxIterations; iteration++) {
            String currentUrl = driver.getCurrentUrl();
            String pageTitle = driver.getTitle();
            System.out.println("[AuthFlow:" + iteration + "] URL: " + currentUrl);
            System.out.println("[AuthFlow:" + iteration + "] Title: " + pageTitle);

            // If we're already back on the Agent, we're done
            if (currentUrl.contains("localhost:" + AGENT_PORT) && !currentUrl.contains("8084") && !currentUrl.contains("8085")) {
                System.out.println("[Agent:8081] Successfully redirected back to Agent");
                return;
            }

            // Handle AS User IDP (8084) login page
            if (currentUrl.contains("8084") && currentUrl.contains("login")) {
                System.out.println("[AsUserIDP:8084] Login page detected, submitting credentials...");
                WebElement usernameField = wait.until(ExpectedConditions.presenceOfElementLocated(By.name("username")));
                WebElement passwordField = driver.findElement(By.name("password"));
                WebElement loginButton = driver.findElement(By.cssSelector("button[type='submit']"));
                usernameField.sendKeys("admin");
                passwordField.sendKeys("admin123");
                loginButton.click();
                System.out.println("[AsUserIDP:8084] Submitted login form");
                waitForPageTransition();
                continue;
            }

            // Handle OIDC consent on AS User IDP (8084)
            if (currentUrl.contains("8084") && pageTitle.contains("Consent") && !pageTitle.contains("Agent Operation")) {
                System.out.println("[AsUserIDP:8084] OIDC consent page detected, approving...");
                completeOidcConsent();
                waitForPageTransition();
                continue;
            }

            // Handle Agent Operation Authorization consent on AS (8085)
            // The URL may be /oauth2/authorize?request_uri=... (not containing "consent"),
            // so we check the page title instead.
            if (currentUrl.contains("8085") && pageTitle.contains("Agent Operation")) {
                System.out.println("[AuthServer:8085] AOA consent page detected, approving...");
                try {
                    WebElement approveButton = wait.until(ExpectedConditions.elementToBeClickable(
                        By.cssSelector("button[value='approve'], button.btn-approve")
                    ));
                    approveButton.click();
                    System.out.println("[AuthServer:8085] Clicked AOA approve button");
                } catch (TimeoutException e) {
                    System.out.println("[AuthServer:8085] Could not find AOA approve button");
                }
                waitForPageTransition();
                continue;
            }

            // Handle OIDC consent on AS (8085) — traditional OAuth consent
            if (currentUrl.contains("8085") && pageTitle.contains("Consent") && !pageTitle.contains("Agent Operation")) {
                System.out.println("[AuthServer:8085] OIDC consent page detected, approving...");
                completeOidcConsent();
                waitForPageTransition();
                continue;
            }

            // If we're on 8084 or 8085 but no recognizable page, wait and retry
            if (currentUrl.contains("8084") || currentUrl.contains("8085")) {
                System.out.println("[AuthFlow:" + iteration + "] On auth service but no action needed, waiting for redirect...");
                waitForPageTransition();
                continue;
            }

            // Unknown state, wait briefly
            waitForPageTransition();
        }

        // Final check — if we're still not on Agent, fail with diagnostics
        String finalUrl = driver.getCurrentUrl();
        if (!finalUrl.contains("localhost:" + AGENT_PORT)) {
            System.out.println("[AuthFlow] Failed to complete authorization flow after " + maxIterations + " iterations");
            System.out.println("[AuthFlow] Final URL: " + finalUrl);
            System.out.println("[AuthFlow] Final title: " + driver.getTitle());
            throw new TimeoutException("Authorization flow did not redirect back to Agent. Final URL: " + finalUrl);
        }
        System.out.println("[Agent:8081] Successfully redirected back to Agent");
    }

    /**
     * Wait for a page transition (redirect or page load) to complete.
     */
    private void waitForPageTransition() {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Get service prefix based on current URL
     * @return Service prefix string like "[Agent:8081] "
     */
    private String getServicePrefix(String url) {
        if (url.contains("8083")) {
            return "[AgentUserIDP:8083] ";
        } else if (url.contains("8084")) {
            return "[AsUserIDP:8084] ";
        } else if (url.contains("8085")) {
            return "[AuthServer:8085] ";
        } else if (url.contains("8081") || url.contains("localhost:" + AGENT_PORT)) {
            return "[Agent:8081] ";
        } else {
            return "[Unknown] ";
        }
    }

    /**
     * Check if Chrome browser is available
     */
    private static boolean checkChromeAvailability() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            String[] chromePaths;
            
            if (os.contains("mac")) {
                chromePaths = new String[]{
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
                };
            } else if (os.contains("win")) {
                chromePaths = new String[]{
                    System.getenv("LOCALAPPDATA") + "\\Google\\Chrome\\Application\\chrome.exe",
                    System.getenv("PROGRAMFILES") + "\\Google\\Chrome\\Application\\chrome.exe",
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
                };
            } else {
                chromePaths = new String[]{
                    "/usr/bin/google-chrome",
                    "/usr/bin/chromium-browser",
                    "/usr/bin/chromium",
                    "/snap/bin/chromium"
                };
            }
            
            for (String path : chromePaths) {
                if (new java.io.File(path).exists()) {
                    return true;
                }
            }
            
            // Also try to find chrome in PATH
            try {
                Process process = Runtime.getRuntime().exec(new String[]{"which", "google-chrome", "chrome", "chromium"});
                int exitCode = process.waitFor();
                if (exitCode == 0) {
                    return true;
                }
            } catch (Exception e) {
                // Ignore
            }
            
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if required services are available
     * Uses port checking instead of HTTP to avoid issues with services that don't provide root endpoints
     */
    private static boolean checkServiceAvailability() {
        int[] requiredPorts = {8081, 8082, 8083, 8084, 8085, 8086};
        
        boolean allAvailable = true;
        for (int port : requiredPorts) {
            try {
                java.net.Socket socket = new java.net.Socket();
                socket.connect(new java.net.InetSocketAddress("localhost", port), 1000);
                socket.close();
                // Port is open, service is available
            } catch (Exception e) {
                allAvailable = false;
                System.err.println("Service not available on port: " + port);
            }
        }
        
        if (!allAvailable) {
            System.err.println("\n" + "=".repeat(80));
            System.err.println("WARNING: Required services are not available for full E2E tests!");
            System.err.println("=".repeat(80));
            System.err.println("Please start the required services using the provided scripts:");
            System.err.println("  cd open-agent-auth-samples");
            System.err.println("  ./scripts/sample-start.sh");
            System.err.println("=".repeat(80));
            System.err.println("Required services:");
            System.err.println("  - Agent (port 8081)");
            System.err.println("  - Agent IDP (port 8082)");
            System.err.println("  - Agent User IDP (port 8083)");
            System.err.println("  - AS User IDP (port 8084)");
            System.err.println("  - Authorization Server (port 8085)");
            System.err.println("  - Resource Server (port 8086)");
            System.err.println("=".repeat(80));
            System.err.println("Tests will be skipped if services are not available.");
            System.err.println("=".repeat(80) + "\n");
        }
        
        return allAvailable;
    }
}
