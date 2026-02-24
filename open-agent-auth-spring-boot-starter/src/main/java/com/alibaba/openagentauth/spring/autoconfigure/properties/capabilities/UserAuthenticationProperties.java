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
package com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities;

import com.alibaba.openagentauth.spring.autoconfigure.properties.CapabilitiesProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * User Authentication capability properties.
 * <p>
 * This class defines configuration for the User Authentication capability,
 * which provides user identity authentication including login page,
 * user registry, and session management.
 * </p>
 * <p>
 * This class is not independently bound via {@code @ConfigurationProperties}.
 * Instead, it is nested within {@link CapabilitiesProperties} and bound as part of
 * the {@code open-agent-auth.capabilities.user-authentication} prefix through the parent class hierarchy.
 * </p>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   capabilities:
 *     user-authentication:
 *       enabled: true
 *       login-page:
 *         enabled: true
 *         title: Identity Provider
 *         subtitle: Please sign in to continue
 *       user-registry:
 *         enabled: true
 *         type: in-memory
 *         preset-users:
 *           - username: admin
 *             password: admin123
 * </pre>
 *
 * @since 2.0
 * @see LoginPageProperties
 * @see UserRegistryProperties
 */
public class UserAuthenticationProperties {

    /**
     * Whether User Authentication capability is enabled.
     * <p>
     * When enabled, the application will provide user authentication functionality
     * including a login page and user identity management.
     * </p>
     * <p>
     * Default value: {@code false}
     * </p>
     */
    private boolean enabled = false;

    /**
     * Login page configuration.
     * <p>
     * Defines the appearance and behavior of the default login page,
     * including titles, labels, and demo user settings.
     * </p>
     */
    private LoginPageProperties loginPage = new LoginPageProperties();

    /**
     * User registry configuration.
     * <p>
     * Defines how users are stored and authenticated, including the
     * registry type and preset users.
     * </p>
     */
    private UserRegistryProperties userRegistry = new UserRegistryProperties();

    /**
     * Gets whether the User Authentication capability is enabled.
     *
     * @return {@code true} if enabled, {@code false} otherwise
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether the User Authentication capability is enabled.
     *
     * @param enabled {@code true} to enable, {@code false} to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the login page configuration.
     *
     * @return the login page configuration
     */
    public LoginPageProperties getLoginPage() {
        return loginPage;
    }

    /**
     * Sets the login page configuration.
     *
     * @param loginPage the login page configuration to set
     */
    public void setLoginPage(LoginPageProperties loginPage) {
        this.loginPage = loginPage;
    }

    /**
     * Gets the user registry configuration.
     *
     * @return the user registry configuration
     */
    public UserRegistryProperties getUserRegistry() {
        return userRegistry;
    }

    /**
     * Sets the user registry configuration.
     *
     * @param userRegistry the user registry configuration to set
     */
    public void setUserRegistry(UserRegistryProperties userRegistry) {
        this.userRegistry = userRegistry;
    }

    /**
     * Login page configuration.
     * <p>
     * This inner class defines the appearance and behavior of the default login page,
     * including titles, labels, buttons, and demo user settings.
     * </p>
     */
    public static class LoginPageProperties {
        /**
         * Whether the default login page is enabled.
         * <p>
         * When enabled, the framework will provide a default login page. When disabled,
         * applications can provide their own custom login page.
         * </p>
         * <p>
         * Default value: {@code true}
         * </p>
         */
        private boolean enabled = true;

        /**
         * Page title displayed in browser tab.
         * <p>
         * The HTML title that appears in the browser tab when viewing the login page.
         * </p>
         * <p>
         * Default value: {@code Identity Provider - Login}
         * </p>
         */
        private String pageTitle = "Identity Provider - Login";

        /**
         * Main title displayed on login page.
         * <p>
         * The large heading displayed at the top of the login page.
         * </p>
         * <p>
         * Default value: {@code Identity Provider}
         * </p>
         */
        private String title = "Identity Provider";

        /**
         * Subtitle displayed below the main title.
         * <p>
         * The smaller text displayed below the main title to provide context.
         * </p>
         * <p>
         * Default value: {@code Please sign in to continue}
         * </p>
         */
        private String subtitle = "Please sign in to continue";

        /**
         * Label for the username field.
         * <p>
         * The text label displayed above the username input field.
         * </p>
         * <p>
         * Default value: {@code Username}
         * </p>
         */
        private String usernameLabel = "Username";

        /**
         * Label for the password field.
         * <p>
         * The text label displayed above the password input field.
         * </p>
         * <p>
         * Default value: {@code Password}
         * </p>
         */
        private String passwordLabel = "Password";

        /**
         * Text for the login button.
         * <p>
         * The text displayed on the submit/login button.
         * </p>
         * <p>
         * Default value: {@code Sign In}
         * </p>
         */
        private String buttonText = "Sign In";

        /**
         * Whether to display demo users information.
         * <p>
         * When enabled, demo user credentials will be displayed on the login page
         * for testing purposes. This should only be used in development environments.
         * </p>
         * <p>
         * Default value: {@code false}
         * </p>
         */
        private boolean showDemoUsers = false;

        /**
         * List of demo users in format "username:password;username2:password2".
         * <p>
         * A semicolon-separated list of demo user credentials. Each entry should be
         * in the format "username:password". Only displayed if {@code showDemoUsers} is true.
         * </p>
         * <p>
         * Default value: empty string
         * </p>
         */
        private String demoUsers = "";

        /**
         * Footer text displayed at the bottom.
         * <p>
         * The text displayed at the bottom of the login page, typically for copyright
         * or additional information.
         * </p>
         * <p>
         * Default value: empty string
         * </p>
         */
        private String footerText = "";

        /**
         * Login page template path.
         * <p>
         * The classpath location of the Thymeleaf template for the login page.
         * Applications can override the default template by providing a custom template
         * at this location.
         * </p>
         * <p>
         * Default value: {@code classpath:/templates/login.html}
         * </p>
         */
        private String template = "classpath:/templates/login.html";

        /**
         * Gets whether the default login page is enabled.
         *
         * @return {@code true} if enabled, {@code false} otherwise
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether the default login page is enabled.
         *
         * @param enabled {@code true} to enable, {@code false} to disable
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets the page title.
         *
         * @return the page title
         */
        public String getPageTitle() {
            return pageTitle;
        }

        /**
         * Sets the page title.
         *
         * @param pageTitle the page title to set
         */
        public void setPageTitle(String pageTitle) {
            this.pageTitle = pageTitle;
        }

        /**
         * Gets the main title.
         *
         * @return the main title
         */
        public String getTitle() {
            return title;
        }

        /**
         * Sets the main title.
         *
         * @param title the main title to set
         */
        public void setTitle(String title) {
            this.title = title;
        }

        /**
         * Gets the subtitle.
         *
         * @return the subtitle
         */
        public String getSubtitle() {
            return subtitle;
        }

        /**
         * Sets the subtitle.
         *
         * @param subtitle the subtitle to set
         */
        public void setSubtitle(String subtitle) {
            this.subtitle = subtitle;
        }

        /**
         * Gets the username label.
         *
         * @return the username label
         */
        public String getUsernameLabel() {
            return usernameLabel;
        }

        /**
         * Sets the username label.
         *
         * @param usernameLabel the username label to set
         */
        public void setUsernameLabel(String usernameLabel) {
            this.usernameLabel = usernameLabel;
        }

        /**
         * Gets the password label.
         *
         * @return the password label
         */
        public String getPasswordLabel() {
            return passwordLabel;
        }

        /**
         * Sets the password label.
         *
         * @param passwordLabel the password label to set
         */
        public void setPasswordLabel(String passwordLabel) {
            this.passwordLabel = passwordLabel;
        }

        /**
         * Gets the button text.
         *
         * @return the button text
         */
        public String getButtonText() {
            return buttonText;
        }

        /**
         * Sets the button text.
         *
         * @param buttonText the button text to set
         */
        public void setButtonText(String buttonText) {
            this.buttonText = buttonText;
        }

        /**
         * Gets whether to display demo users.
         *
         * @return {@code true} if demo users should be displayed, {@code false} otherwise
         */
        public boolean isShowDemoUsers() {
            return showDemoUsers;
        }

        /**
         * Sets whether to display demo users.
         *
         * @param showDemoUsers {@code true} to display demo users, {@code false} to hide
         */
        public void setShowDemoUsers(boolean showDemoUsers) {
            this.showDemoUsers = showDemoUsers;
        }

        /**
         * Gets the demo users string.
         *
         * @return the demo users string
         */
        public String getDemoUsers() {
            return demoUsers;
        }

        /**
         * Sets the demo users string.
         *
         * @param demoUsers the demo users string to set
         */
        public void setDemoUsers(String demoUsers) {
            this.demoUsers = demoUsers;
        }

        /**
         * Gets the footer text.
         *
         * @return the footer text
         */
        public String getFooterText() {
            return footerText;
        }

        /**
         * Sets the footer text.
         *
         * @param footerText the footer text to set
         */
        public void setFooterText(String footerText) {
            this.footerText = footerText;
        }

        /**
         * Gets the template path.
         *
         * @return the template path
         */
        public String getTemplate() {
            return template;
        }

        /**
         * Sets the template path.
         *
         * @param template the template path to set
         */
        public void setTemplate(String template) {
            this.template = template;
        }
    }

    /**
     * User registry configuration.
     * <p>
     * This inner class defines how users are stored and authenticated,
     * including the registry type and preset users.
     * </p>
     */
    public static class UserRegistryProperties {
        /**
         * Whether user registry is enabled.
         * <p>
         * When enabled, the application will authenticate users against the configured
         * user registry. When disabled, user authentication will be skipped.
         * </p>
         * <p>
         * Default value: {@code true}
         * </p>
         */
        private boolean enabled = true;

        /**
         * User registry type.
         * <p>
         * The type of user registry to use. Supported values include:
         * <ul>
         *   <li>{@code in-memory} - Users stored in memory (for development/testing)</li>
         * </ul>
         * </p>
         * <p>
         * Default value: {@code in-memory}
         * </p>
         */
        private String type = "in-memory";

        /**
         * Preset users configuration.
         * <p>
         * A list of pre-configured users that will be available for authentication.
         * This is primarily used with the {@code in-memory} registry type.
         * </p>
         * <p>
         * Default value: empty list
         * </p>
         */
        private List<PresetUserProperties> presetUsers = new ArrayList<>();

        /**
         * Gets whether user registry is enabled.
         *
         * @return {@code true} if enabled, {@code false} otherwise
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether user registry is enabled.
         *
         * @param enabled {@code true} to enable, {@code false} to disable
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Gets the user registry type.
         *
         * @return the user registry type
         */
        public String getType() {
            return type;
        }

        /**
         * Sets the user registry type.
         *
         * @param type the user registry type to set
         */
        public void setType(String type) {
            this.type = type;
        }

        /**
         * Gets the preset users.
         *
         * @return the list of preset users
         */
        public List<PresetUserProperties> getPresetUsers() {
            return presetUsers;
        }

        /**
         * Sets the preset users.
         *
         * @param presetUsers the list of preset users to set
         */
        public void setPresetUsers(List<PresetUserProperties> presetUsers) {
            this.presetUsers = presetUsers;
        }

        /**
         * Preset user configuration.
         * <p>
         * This inner class defines the configuration for a single preset user,
         * including username, password, and profile information.
         * </p>
         */
        public static class PresetUserProperties {
            /**
             * Username.
             * <p>
             * The unique username used for authentication.
             * </p>
             */
            private String username;

            /**
             * Password.
             * <p>
             * The password used for authentication. In production, this should be
             * stored as a hashed value.
             * </p>
             */
            private String password;

            /**
             * Subject identifier.
             * <p>
             * The unique subject identifier for the user, typically used in OIDC tokens.
             * If not specified, the username will be used as the subject.
             * </p>
             */
            private String subject;

            /**
             * Email.
             * <p>
             * The user's email address, included in user profile information.
             * </p>
             */
            private String email;

            /**
             * Display name.
             * <p>
             * The user's display name, included in user profile information.
             * </p>
             */
            private String name;

            /**
             * Gets the username.
             *
             * @return the username
             */
            public String getUsername() {
                return username;
            }

            /**
             * Sets the username.
             *
             * @param username the username to set
             */
            public void setUsername(String username) {
                this.username = username;
            }

            /**
             * Gets the password.
             *
             * @return the password
             */
            public String getPassword() {
                return password;
            }

            /**
             * Sets the password.
             *
             * @param password the password to set
             */
            public void setPassword(String password) {
                this.password = password;
            }

            /**
             * Gets the subject identifier.
             *
             * @return the subject identifier
             */
            public String getSubject() {
                return subject;
            }

            /**
             * Sets the subject identifier.
             *
             * @param subject the subject identifier to set
             */
            public void setSubject(String subject) {
                this.subject = subject;
            }

            /**
             * Gets the email.
             *
             * @return the email
             */
            public String getEmail() {
                return email;
            }

            /**
             * Sets the email.
             *
             * @param email the email to set
             */
            public void setEmail(String email) {
                this.email = email;
            }

            /**
             * Gets the display name.
             *
             * @return the display name
             */
            public String getName() {
                return name;
            }

            /**
             * Sets the display name.
             *
             * @param name the display name to set
             */
            public void setName(String name) {
                this.name = name;
            }
        }
    }
}