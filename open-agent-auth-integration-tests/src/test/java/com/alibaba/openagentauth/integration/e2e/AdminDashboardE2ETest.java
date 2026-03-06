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

import io.github.bonigarcia.wdm.WebDriverManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.openqa.selenium.By;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.io.File;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * E2E tests for the Admin Dashboard on Agent IDP (port 8082).
 * <p>
 * This test class validates the complete admin dashboard flow:
 * <ol>
 *   <li>First, perform a deterministic agent conversation to generate audit/binding data</li>
 *   <li>Then, access the Agent IDP admin dashboard and complete the OAuth2 login flow</li>
 *   <li>Verify the dashboard layout, navigation sidebar, and sub-page content</li>
 * </ol>
 * </p>
 * <p>
 * The Agent IDP (8082) has admin enabled with access-control disabled for demo purposes.
 * Accessing {@code /admin} triggers an OAuth2 login redirect to Agent User IDP (8083),
 * after which the user is redirected back to the admin dashboard.
 * </p>
 *
 * @since 1.0
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("Admin Dashboard E2E Tests")
class AdminDashboardE2ETest {

    private static final int AGENT_PORT = 8081;
    private static final int AGENT_IDP_PORT = 8082;
    private static final int AGENT_USER_IDP_PORT = 8083;
    private static final int AS_USER_IDP_PORT = 8084;
    private static final int AUTH_SERVER_PORT = 8085;
    private static final int RESOURCE_SERVER_PORT = 8086;

    private static final String AGENT_IDP_ADMIN_URL = "http://localhost:" + AGENT_IDP_PORT + "/admin";
    private static final String AGENT_URL = "http://localhost:" + AGENT_PORT;

    private WebDriver driver;
    private WebDriverWait wait;

    private static boolean servicesAvailable;
    private static boolean chromeAvailable;

    @BeforeAll
    static void setupClass() {
        String enableTests = System.getProperty("ENABLE_INTEGRATION_TESTS",
                System.getenv("ENABLE_INTEGRATION_TESTS"));
        if (!"true".equalsIgnoreCase(enableTests)) {
            servicesAvailable = false;
            chromeAvailable = false;
            return;
        }

        chromeAvailable = checkChromeAvailability();
        servicesAvailable = chromeAvailable && checkServiceAvailability();
    }

    @BeforeEach
    void setUp() {
        assumeTrue(servicesAvailable, "Required services are not available");
        assumeTrue(chromeAvailable, "Chrome browser is not available");

        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless=new");
        options.addArguments("--no-sandbox");
        options.addArguments("--disable-dev-shm-usage");
        options.addArguments("--disable-gpu");
        options.addArguments("--window-size=1920,1080");

        driver = new ChromeDriver(options);
        wait = new WebDriverWait(driver, Duration.ofSeconds(30));
    }

    @AfterEach
    void tearDown() {
        if (driver != null) {
            driver.quit();
        }
    }

    // ========================================================================
    // Test 1: Perform a deterministic agent conversation to generate data
    // ========================================================================

    @Test
    @Order(1)
    @DisplayName("Should complete agent conversation to generate audit and binding data")
    void shouldCompleteAgentConversationToGenerateData() {
        assumeTrue(servicesAvailable, "Required services are not available");

        System.out.println("\n========================================");
        System.out.println("Step 1: Agent conversation to generate data");
        System.out.println("========================================\n");

        // Navigate to Agent (8081)
        driver.get(AGENT_URL);
        waitForPageTransition();

        String currentUrl = driver.getCurrentUrl();
        System.out.println("[Agent:8081] Current URL: " + currentUrl);

        // If redirected to Agent User IDP login, complete authentication
        if (currentUrl.contains(":" + AGENT_USER_IDP_PORT)) {
            System.out.println("[Agent:8081] Redirected to Agent User IDP for login");
            completeAgentUserIdpAuthentication();

            // Handle OIDC consent if present
            waitForPageTransition();
            currentUrl = driver.getCurrentUrl();
            if (driver.getTitle().contains("Consent")) {
                System.out.println("Detected OIDC consent page, completing...");
                completeOidcConsent();
                waitForPageTransition();
            }

            // Wait for redirect back to Agent
            wait.until(ExpectedConditions.urlContains("localhost:" + AGENT_PORT));
            System.out.println("[Agent:8081] Successfully authenticated and redirected to Agent");
        }

        // Perform a conversation: search watch
        completeConversationWithAuthorization("search watch", "search_products", "watch");

        System.out.println("\n========================================");
        System.out.println("Agent conversation completed successfully!");
        System.out.println("========================================\n");
    }

    // ========================================================================
    // Test 2: Access admin dashboard and complete OAuth2 login
    // ========================================================================

    @Test
    @Order(2)
    @DisplayName("Should access Agent IDP admin and complete OAuth2 login flow")
    void shouldAccessAdminAndCompleteOAuth2Login() {
        assumeTrue(servicesAvailable, "Required services are not available");

        System.out.println("\n========================================");
        System.out.println("Step 2: Admin dashboard OAuth2 login flow");
        System.out.println("========================================\n");

        // Navigate to Agent IDP admin page
        System.out.println("[AgentIDP:8082] Navigating to " + AGENT_IDP_ADMIN_URL);
        driver.get(AGENT_IDP_ADMIN_URL);
        waitForPageTransition();

        String currentUrl = driver.getCurrentUrl();
        String pageTitle = driver.getTitle();
        System.out.println("[AgentIDP:8082] Current URL: " + currentUrl);
        System.out.println("[AgentIDP:8082] Page title: " + pageTitle);

        // Should be redirected to Agent User IDP (8083) for login
        if (currentUrl.contains(":" + AGENT_USER_IDP_PORT) && currentUrl.contains("login")) {
            System.out.println("[AgentUserIDP:8083] Login page detected, submitting credentials...");
            completeAgentUserIdpAuthentication();
            waitForPageTransition();

            // Handle OIDC consent if present
            currentUrl = driver.getCurrentUrl();
            pageTitle = driver.getTitle();
            System.out.println("[Auth] After login - URL: " + currentUrl + ", Title: " + pageTitle);

            if (pageTitle.contains("Consent")) {
                System.out.println("[AgentUserIDP:8083] OIDC consent page detected, approving...");
                completeOidcConsent();
                waitForPageTransition();
            }
        }

        // Wait for redirect back to Agent IDP admin
        currentUrl = driver.getCurrentUrl();
        System.out.println("[AgentIDP:8082] After auth flow - URL: " + currentUrl);

        // Should now be on the admin dashboard
        wait.until(ExpectedConditions.urlContains("localhost:" + AGENT_IDP_PORT));
        currentUrl = driver.getCurrentUrl();
        pageTitle = driver.getTitle();
        System.out.println("[AgentIDP:8082] Final URL: " + currentUrl);
        System.out.println("[AgentIDP:8082] Final title: " + pageTitle);

        assertThat(currentUrl).contains("/admin");
        assertThat(pageTitle).contains("Admin Dashboard");

        System.out.println("[AgentIDP:8082] ✓ Admin dashboard loaded successfully after OAuth2 login");
    }

    // ========================================================================
    // Test 3: Verify admin dashboard layout and navigation
    // ========================================================================

    @Test
    @Order(3)
    @DisplayName("Should display admin dashboard with sidebar navigation and content frame")
    void shouldDisplayAdminDashboardWithNavigation() {
        assumeTrue(servicesAvailable, "Required services are not available");

        System.out.println("\n========================================");
        System.out.println("Step 3: Verify admin dashboard layout");
        System.out.println("========================================\n");

        // Login and navigate to admin
        loginAndNavigateToAdmin();

        // Verify sidebar exists
        WebElement sidebar = wait.until(ExpectedConditions.presenceOfElementLocated(By.className("sidebar")));
        assertThat(sidebar.isDisplayed()).isTrue();
        System.out.println("[AdminDashboard] ✓ Sidebar is displayed");

        // Verify sidebar brand/title
        WebElement sidebarTitle = sidebar.findElement(By.className("sidebar-title"));
        assertThat(sidebarTitle.getText()).isEqualTo("OAA Admin");
        System.out.println("[AdminDashboard] ✓ Sidebar title: " + sidebarTitle.getText());

        WebElement sidebarSubtitle = sidebar.findElement(By.className("sidebar-subtitle"));
        assertThat(sidebarSubtitle.getText()).isEqualToIgnoringCase("Management Console");
        System.out.println("[AdminDashboard] ✓ Sidebar subtitle: " + sidebarSubtitle.getText());

        // Verify navigation items exist
        List<WebElement> navItems = sidebar.findElements(By.className("nav-item"));
        assertThat(navItems).isNotEmpty();
        System.out.println("[AdminDashboard] ✓ Found " + navItems.size() + " navigation items");

        for (WebElement navItem : navItems) {
            String label = navItem.getText().trim();
            String dataUrl = navItem.getAttribute("data-url");
            System.out.println("[AdminDashboard]   - " + label + " → " + dataUrl);
        }

        // Verify first nav item is active by default
        WebElement firstNavItem = navItems.get(0);
        assertThat(firstNavItem.getAttribute("class")).contains("active");
        System.out.println("[AdminDashboard] ✓ First nav item is active");

        // Verify content frame (iframe) exists
        WebElement contentFrame = wait.until(ExpectedConditions.presenceOfElementLocated(By.id("contentFrame")));
        assertThat(contentFrame.isDisplayed()).isTrue();
        String frameSrc = contentFrame.getAttribute("src");
        assertThat(frameSrc).contains("embedded=true");
        System.out.println("[AdminDashboard] ✓ Content frame loaded: " + frameSrc);

        // Verify main content area exists
        WebElement mainContent = driver.findElement(By.id("mainContent"));
        assertThat(mainContent.isDisplayed()).isTrue();
        System.out.println("[AdminDashboard] ✓ Main content area is displayed");

        System.out.println("[AdminDashboard] ✓ Dashboard layout verification complete");
    }

    // ========================================================================
    // Test 4: Verify navigation between admin sub-pages
    // ========================================================================

    @Test
    @Order(4)
    @DisplayName("Should navigate between admin sub-pages via sidebar")
    void shouldNavigateBetweenAdminSubPages() {
        assumeTrue(servicesAvailable, "Required services are not available");

        System.out.println("\n========================================");
        System.out.println("Step 4: Verify sub-page navigation");
        System.out.println("========================================\n");

        // Login and navigate to admin
        loginAndNavigateToAdmin();

        // Get all navigation items
        WebElement sidebar = wait.until(ExpectedConditions.presenceOfElementLocated(By.className("sidebar")));
        List<WebElement> navItems = sidebar.findElements(By.className("nav-item"));
        assertThat(navItems).hasSizeGreaterThanOrEqualTo(1);

        // Click each nav item and verify the iframe src changes
        for (int i = 0; i < navItems.size(); i++) {
            WebElement navItem = navItems.get(i);
            String label = navItem.getText().trim();
            String expectedUrl = navItem.getAttribute("data-url");

            System.out.println("[AdminNav] Clicking: " + label);
            navItem.click();

            // Brief wait for iframe to update
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // Verify the clicked item becomes active
            assertThat(navItem.getAttribute("class")).contains("active");
            System.out.println("[AdminNav] ✓ " + label + " is now active");

            // Verify other items are not active
            for (int j = 0; j < navItems.size(); j++) {
                if (j != i) {
                    assertThat(navItems.get(j).getAttribute("class")).doesNotContain("active");
                }
            }

            // Verify iframe src updated
            WebElement contentFrame = driver.findElement(By.id("contentFrame"));
            String frameSrc = contentFrame.getAttribute("src");
            assertThat(frameSrc).contains(expectedUrl);
            System.out.println("[AdminNav] ✓ Content frame updated to: " + frameSrc);
        }

        System.out.println("[AdminNav] ✓ All sub-page navigation verified");
    }

    // ========================================================================
    // Test 5: Verify workloads sub-page content
    // ========================================================================

    @Test
    @Order(5)
    @DisplayName("Should display workloads management page with content")
    void shouldDisplayWorkloadsPage() {
        assumeTrue(servicesAvailable, "Required services are not available");

        System.out.println("\n========================================");
        System.out.println("Step 5: Verify workloads sub-page");
        System.out.println("========================================\n");

        // Access workloads page directly (embedded mode)
        loginAndNavigateToAdmin();

        // Navigate to workloads via sidebar
        WebElement sidebar = wait.until(ExpectedConditions.presenceOfElementLocated(By.className("sidebar")));
        List<WebElement> navItems = sidebar.findElements(By.className("nav-item"));

        WebElement workloadsNav = navItems.stream()
                .filter(item -> item.getText().trim().contains("Workload"))
                .findFirst()
                .orElse(null);

        if (workloadsNav != null) {
            workloadsNav.click();
            waitForPageTransition();

            // Switch to iframe to verify content
            WebElement contentFrame = driver.findElement(By.id("contentFrame"));
            driver.switchTo().frame(contentFrame);

            // Wait for page to load inside iframe
            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // Verify the workloads page has loaded (check for page body content)
            String pageSource = driver.getPageSource();
            assertThat(pageSource).isNotEmpty();
            System.out.println("[Workloads] ✓ Workloads page loaded in iframe");
            System.out.println("[Workloads] Page source length: " + pageSource.length());

            // Switch back to main content
            driver.switchTo().defaultContent();
        } else {
            System.out.println("[Workloads] Workload nav item not found (may not be enabled)");
        }

        System.out.println("[Workloads] ✓ Workloads page verification complete");
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Login to Agent User IDP and navigate to the admin dashboard.
     * This is a reusable helper for tests that need an authenticated admin session.
     */
    private void loginAndNavigateToAdmin() {
        driver.get(AGENT_IDP_ADMIN_URL);
        waitForPageTransition();

        String currentUrl = driver.getCurrentUrl();

        // Complete login if redirected to Agent User IDP
        if (currentUrl.contains(":" + AGENT_USER_IDP_PORT)) {
            completeAgentUserIdpAuthentication();
            waitForPageTransition();

            // Handle OIDC consent if present
            if (driver.getTitle().contains("Consent")) {
                completeOidcConsent();
                waitForPageTransition();
            }
        }

        // Wait for admin dashboard to load
        wait.until(ExpectedConditions.urlContains("localhost:" + AGENT_IDP_PORT));
        wait.until(ExpectedConditions.titleContains("Admin Dashboard"));
        System.out.println("[AdminHelper] ✓ Logged in and navigated to admin dashboard");
    }

    /**
     * Complete Agent User IDP authentication with demo credentials.
     */
    private void completeAgentUserIdpAuthentication() {
        System.out.println("[AgentUserIDP:8083] Starting authentication...");

        WebElement usernameField = wait.until(ExpectedConditions.presenceOfElementLocated(
                By.name("username")
        ));
        WebElement passwordField = driver.findElement(By.name("password"));
        WebElement loginButton = driver.findElement(By.cssSelector("button[type='submit']"));

        usernameField.sendKeys("alice");
        passwordField.sendKeys("password123");
        loginButton.click();
        System.out.println("[AgentUserIDP:8083] Submitted login form");
    }

    /**
     * Complete OIDC consent flow by clicking the approve button.
     */
    private void completeOidcConsent() {
        String consentUrl = driver.getCurrentUrl();
        System.out.println("[OIDCConsent] Completing consent at: " + consentUrl);

        WebElement approveButton = wait.until(ExpectedConditions.elementToBeClickable(
                By.cssSelector("button.btn-approve")
        ));
        approveButton.click();
        System.out.println("[OIDCConsent] Clicked approve button");
    }

    /**
     * Perform a conversation with the Agent that may require authorization.
     * Adapted from FullAuthorizationFlowE2ETest.
     */
    private void completeConversationWithAuthorization(String message, String expectedTool, String expectedKeyword) {
        System.out.println("\n========================================");
        System.out.println("Starting Conversation: " + message);
        System.out.println("========================================\n");

        // Find and fill the message input
        WebElement messageInput = wait.until(ExpectedConditions.presenceOfElementLocated(
                By.id("messageInput")
        ));
        messageInput.sendKeys(message);

        // Click send button
        WebElement sendButton = driver.findElement(By.cssSelector("button.btn-send"));
        sendButton.click();
        System.out.println("[Agent:8081] Sent message: \"" + message + "\"");

        // Wait for response
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        String currentUrl = driver.getCurrentUrl();
        System.out.println("[Agent:8081] Current URL after sending message: " + currentUrl);

        // Check for authorization redirect or link
        WebElement chatMessages = driver.findElement(By.id("chatMessages"));
        List<WebElement> authLinks = chatMessages.findElements(By.className("action-card-auth-link"));

        if (!authLinks.isEmpty()) {
            System.out.println("[Agent:8081] Authorization link found, completing authorization...");
            String authUrl = authLinks.get(0).getAttribute("href");
            System.out.println("[Agent:8081] Authorization URL: " + authUrl);

            driver.get(authUrl);
            waitForPageTransition();

            currentUrl = driver.getCurrentUrl();
            if (currentUrl.contains("" + AS_USER_IDP_PORT) || currentUrl.contains("" + AUTH_SERVER_PORT)) {
                completeAuthorizationServerFlow();
                wait.until(ExpectedConditions.urlContains("localhost:" + AGENT_PORT));
            }

            // Wait for tool execution
            try {
                Thread.sleep(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        // Verify conversation completed
        try {
            chatMessages = wait.until(ExpectedConditions.presenceOfElementLocated(By.id("chatMessages")));
        } catch (TimeoutException e) {
            System.out.println("[Agent:8081] Timeout waiting for chatMessages");
            throw e;
        }

        List<WebElement> messages = chatMessages.findElements(By.className("message"));
        boolean toolExecuted = messages.stream()
                .anyMatch(msg -> msg.getText().toLowerCase().contains(expectedKeyword.toLowerCase())
                        || msg.getText().contains(expectedTool));
        assertThat(toolExecuted).isTrue();
        System.out.println("[Agent:8081] ✓ Conversation completed successfully!");
    }

    /**
     * Complete the Authorization Server flow, handling login, consent, and AOA pages.
     * Adapted from FullAuthorizationFlowE2ETest.
     */
    private void completeAuthorizationServerFlow() {
        waitForPageTransition();

        int maxIterations = 10;
        for (int iteration = 0; iteration < maxIterations; iteration++) {
            String currentUrl = driver.getCurrentUrl();
            String pageTitle = driver.getTitle();
            System.out.println("[AuthFlow:" + iteration + "] URL: " + currentUrl);
            System.out.println("[AuthFlow:" + iteration + "] Title: " + pageTitle);

            // Back on Agent — done
            if (currentUrl.contains("localhost:" + AGENT_PORT)
                    && !currentUrl.contains("" + AS_USER_IDP_PORT)
                    && !currentUrl.contains("" + AUTH_SERVER_PORT)) {
                System.out.println("[Agent:8081] Successfully redirected back to Agent");
                return;
            }

            // AS User IDP login
            if (currentUrl.contains("" + AS_USER_IDP_PORT) && currentUrl.contains("login")) {
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

            // OIDC consent on AS User IDP
            if (currentUrl.contains("" + AS_USER_IDP_PORT) && pageTitle.contains("Consent")
                    && !pageTitle.contains("Agent Operation")) {
                System.out.println("[AsUserIDP:8084] OIDC consent page detected, approving...");
                completeOidcConsent();
                waitForPageTransition();
                continue;
            }

            // AOA consent on Authorization Server
            if (currentUrl.contains("" + AUTH_SERVER_PORT) && pageTitle.contains("Agent Operation")) {
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

            // OIDC consent on Authorization Server
            if (currentUrl.contains("" + AUTH_SERVER_PORT) && pageTitle.contains("Consent")
                    && !pageTitle.contains("Agent Operation")) {
                System.out.println("[AuthServer:8085] OIDC consent page detected, approving...");
                completeOidcConsent();
                waitForPageTransition();
                continue;
            }

            // Unknown state, wait
            waitForPageTransition();
        }

        String finalUrl = driver.getCurrentUrl();
        if (!finalUrl.contains("localhost:" + AGENT_PORT)) {
            throw new RuntimeException("Authorization flow did not redirect back to Agent. Final URL: " + finalUrl);
        }
    }

    /**
     * Wait for a page transition to complete.
     */
    private void waitForPageTransition() {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Check if Chrome browser is available.
     */
    private static boolean checkChromeAvailability() {
        try {
            String operatingSystem = System.getProperty("os.name").toLowerCase();
            String[] chromePaths;

            if (operatingSystem.contains("mac")) {
                chromePaths = new String[]{
                        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
                };
            } else if (operatingSystem.contains("win")) {
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
                if (new File(path).exists()) {
                    return true;
                }
            }

            try {
                Process process = Runtime.getRuntime().exec(new String[]{"which", "google-chrome"});
                return process.waitFor() == 0;
            } catch (Exception ignored) {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if all required services are available.
     */
    private static boolean checkServiceAvailability() {
        int[] requiredPorts = {AGENT_PORT, AGENT_IDP_PORT, AGENT_USER_IDP_PORT,
                AS_USER_IDP_PORT, AUTH_SERVER_PORT, RESOURCE_SERVER_PORT};

        boolean allAvailable = true;
        for (int port : requiredPorts) {
            try {
                Socket socket = new Socket();
                socket.connect(new InetSocketAddress("localhost", port), 1000);
                socket.close();
            } catch (Exception e) {
                allAvailable = false;
                System.err.println("Service not available on port: " + port);
            }
        }

        if (!allAvailable) {
            System.err.println("\n" + "=".repeat(80));
            System.err.println("WARNING: Required services are not available for Admin Dashboard E2E tests!");
            System.err.println("=".repeat(80));
            System.err.println("Please start the required services using:");
            System.err.println("  cd open-agent-auth-samples && ./scripts/sample-start.sh");
            System.err.println("=".repeat(80) + "\n");
        }

        return allAvailable;
    }
}
