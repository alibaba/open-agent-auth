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
package com.alibaba.openagentauth.core.model.oidc;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;
import java.util.Objects;

/**
 * Represents the UserInfo response from OpenID Connect.
 * <p>
 * This class encapsulates the claims about the Authentication Event and the End-User
 * that are returned by the UserInfo Endpoint. These claims are represented as a JSON
 * object that contains a set of name and value pairs for the Claims.
 * </p>
 * <p>
 * <b>Standard Claims:</b></p>
 * <ul>
 *   <li><b>sub:</b> REQUIRED - Subject identifier</li>
 *   <li><b>name:</b> OPTIONAL - End-User's full name</li>
 *   <li><b>given_name:</b> OPTIONAL - End-User's given name(s)</li>
 *   <li><b>family_name:</b> OPTIONAL - End-User's family name(s)</li>
 *   <li><b>middle_name:</b> OPTIONAL - End-User's middle name(s)</li>
 *   <li><b>nickname:</b> OPTIONAL - End-User's nickname(s)</li>
 *   <li><b>preferred_username:</b> OPTIONAL - End-User's preferred username</li>
 *   <li><b>profile:</b> OPTIONAL - URL of End-User's profile page</li>
 *   <li><b>picture:</b> OPTIONAL - URL of End-User's profile picture</li>
 *   <li><b>website:</b> OPTIONAL - URL of End-User's web page or blog</li>
 *   <li><b>email:</b> OPTIONAL - End-User's preferred email address</li>
 *   <li><b>email_verified:</b> OPTIONAL - True if email has been verified</li>
 *   <li><b>gender:</b> OPTIONAL - End-User's gender</li>
 *   <li><b>birthdate:</b> OPTIONAL - End-User's birthday</li>
 *   <li><b>zoneinfo:</b> OPTIONAL - End-User's time zone</li>
 *   <li><b>locale:</b> OPTIONAL - End-User's locale</li>
 *   <li><b>phone_number:</b> OPTIONAL - End-User's preferred telephone number</li>
 *   <li><b>phone_number_verified:</b> OPTIONAL - True if phone number has been verified</li>
 *   <li><b>address:</b> OPTIONAL - End-User's postal address</li>
 *   <li><b>updated_at:</b> OPTIONAL - Time the End-User's information was last updated</li>
 * </ul>
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OpenID Connect Core 1.0 - UserInfo</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserInfo {

    /**
     * Subject identifier.
     * <p>
     * REQUIRED. Subject - Identifier for the End-User at the Issuer.
     * </p>
     */
    private final String sub;

    /**
     * End-User's full name.
     * <p>
     * OPTIONAL. End-User's full name in displayable form including all name parts,
     * possibly including titles and suffixes, ordered according to the End-User's
     * locale and preferences.
     * </p>
     */
    private final String name;

    /**
     * End-User's given name(s).
     * <p>
     * OPTIONAL. Given name(s) or first name(s) of the End-User.
     * </p>
     */
    private final String givenName;

    /**
     * End-User's family name(s).
     * <p>
     * OPTIONAL. Family name(s) or last name(s) of the End-User.
     * </p>
     */
    private final String familyName;

    /**
     * End-User's middle name(s).
     * <p>
     * OPTIONAL. Middle name(s) of the End-User.
     * </p>
     */
    private final String middleName;

    /**
     * End-User's nickname(s).
     * <p>
     * OPTIONAL. Casual name of the End-User that may or may not be the same as the
     * given_name.
     * </p>
     */
    private final String nickname;

    /**
     * End-User's preferred username.
     * <p>
     * OPTIONAL. Shorthand name by which the End-User wishes to be referred to at the RP.
     * </p>
     */
    private final String preferredUsername;

    /**
     * URL of End-User's profile page.
     * <p>
     * OPTIONAL. URL of the End-User's profile page.
     * </p>
     */
    private final String profile;

    /**
     * URL of End-User's profile picture.
     * <p>
     * OPTIONAL. URL of the End-User's profile picture.
     * </p>
     */
    private final String picture;

    /**
     * URL of End-User's web page or blog.
     * <p>
     * OPTIONAL. URL of the End-User's web page or blog.
     * </p>
     */
    private final String website;

    /**
     * End-User's preferred email address.
     * <p>
     * OPTIONAL. End-User's preferred e-mail address.
     * </p>
     */
    private final String email;

    /**
     * True if email has been verified.
     * <p>
     * OPTIONAL. True if the End-User's e-mail address has been verified; otherwise false.
     * </p>
     */
    private final Boolean emailVerified;

    /**
     * End-User's gender.
     * <p>
     * OPTIONAL. End-User's gender.
     * </p>
     */
    private final String gender;

    /**
     * End-User's birthday.
     * <p>
     * OPTIONAL. End-User's birthday.
     * </p>
     */
    private final String birthdate;

    /**
     * End-User's time zone.
     * <p>
     * OPTIONAL. End-User's time zone, e.g., 'America/Los_Angeles' or 'Europe/Paris'.
     * </p>
     */
    private final String zoneinfo;

    /**
     * End-User's locale.
     * <p>
     * OPTIONAL. End-User's locale, represented as a BCP 47 [RFC5646] language tag.
     * </p>
     */
    private final String locale;

    /**
     * End-User's preferred telephone number.
     * <p>
     * OPTIONAL. End-User's preferred telephone number.
     * </p>
     */
    private final String phoneNumber;

    /**
     * True if phone number has been verified.
     * <p>
     * OPTIONAL. True if the End-User's phone number has been verified; otherwise false.
     * </p>
     */
    private final Boolean phoneNumberVerified;

    /**
     * End-User's postal address.
     * <p>
     * OPTIONAL. End-User's preferred postal address.
     * </p>
     */
    private final Address address;

    /**
     * Time the End-User's information was last updated.
     * <p>
     * OPTIONAL. Time the End-User's information was last updated.
     * </p>
     */
    private final Long updatedAt;

    /**
     * Additional claims.
     * <p>
     * OPTIONAL. Additional custom claims.
     * </p>
     */
    private final Map<String, Object> additionalClaims;

    private UserInfo(Builder builder) {
        this.sub = builder.sub;
        this.name = builder.name;
        this.givenName = builder.givenName;
        this.familyName = builder.familyName;
        this.middleName = builder.middleName;
        this.nickname = builder.nickname;
        this.preferredUsername = builder.preferredUsername;
        this.profile = builder.profile;
        this.picture = builder.picture;
        this.website = builder.website;
        this.email = builder.email;
        this.emailVerified = builder.emailVerified;
        this.gender = builder.gender;
        this.birthdate = builder.birthdate;
        this.zoneinfo = builder.zoneinfo;
        this.locale = builder.locale;
        this.phoneNumber = builder.phoneNumber;
        this.phoneNumberVerified = builder.phoneNumberVerified;
        this.address = builder.address;
        this.updatedAt = builder.updatedAt;
        this.additionalClaims = builder.additionalClaims;
    }

    public String getSub() {
        return sub;
    }

    public String getName() {
        return name;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getMiddleName() {
        return middleName;
    }

    public String getNickname() {
        return nickname;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

    public String getProfile() {
        return profile;
    }

    public String getPicture() {
        return picture;
    }

    public String getWebsite() {
        return website;
    }

    public String getEmail() {
        return email;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public String getGender() {
        return gender;
    }

    public String getBirthdate() {
        return birthdate;
    }

    public String getZoneinfo() {
        return zoneinfo;
    }

    public String getLocale() {
        return locale;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public Boolean getPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public Address getAddress() {
        return address;
    }

    public Long getUpdatedAt() {
        return updatedAt;
    }

    public Map<String, Object> getAdditionalClaims() {
        return additionalClaims;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserInfo userInfo = (UserInfo) o;
        return Objects.equals(sub, userInfo.sub) &&
               Objects.equals(name, userInfo.name) &&
               Objects.equals(email, userInfo.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sub, name, email);
    }

    @Override
    public String toString() {
        return "UserInfo{" +
                "sub='" + sub + '\'' +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link UserInfo}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link UserInfo}.
     */
    public static class Builder {
        private String sub;
        private String name;
        private String givenName;
        private String familyName;
        private String middleName;
        private String nickname;
        private String preferredUsername;
        private String profile;
        private String picture;
        private String website;
        private String email;
        private Boolean emailVerified;
        private String gender;
        private String birthdate;
        private String zoneinfo;
        private String locale;
        private String phoneNumber;
        private Boolean phoneNumberVerified;
        private Address address;
        private Long updatedAt;
        private Map<String, Object> additionalClaims;

        /**
         * Sets the subject identifier.
         *
         * @param sub the subject identifier
         * @return this builder instance
         */
        public Builder sub(String sub) {
            this.sub = sub;
            return this;
        }

        /**
         * Sets the full name.
         *
         * @param name the full name
         * @return this builder instance
         */
        public Builder name(String name) {
            this.name = name;
            return this;
        }

        /**
         * Sets the given name.
         *
         * @param givenName the given name
         * @return this builder instance
         */
        public Builder givenName(String givenName) {
            this.givenName = givenName;
            return this;
        }

        /**
         * Sets the family name.
         *
         * @param familyName the family name
         * @return this builder instance
         */
        public Builder familyName(String familyName) {
            this.familyName = familyName;
            return this;
        }

        /**
         * Sets the middle name.
         *
         * @param middleName the middle name
         * @return this builder instance
         */
        public Builder middleName(String middleName) {
            this.middleName = middleName;
            return this;
        }

        /**
         * Sets the nickname.
         *
         * @param nickname the nickname
         * @return this builder instance
         */
        public Builder nickname(String nickname) {
            this.nickname = nickname;
            return this;
        }

        /**
         * Sets the preferred username.
         *
         * @param preferredUsername the preferred username
         * @return this builder instance
         */
        public Builder preferredUsername(String preferredUsername) {
            this.preferredUsername = preferredUsername;
            return this;
        }

        /**
         * Sets the profile URL.
         *
         * @param profile the profile URL
         * @return this builder instance
         */
        public Builder profile(String profile) {
            this.profile = profile;
            return this;
        }

        /**
         * Sets the picture URL.
         *
         * @param picture the picture URL
         * @return this builder instance
         */
        public Builder picture(String picture) {
            this.picture = picture;
            return this;
        }

        /**
         * Sets the website URL.
         *
         * @param website the website URL
         * @return this builder instance
         */
        public Builder website(String website) {
            this.website = website;
            return this;
        }

        /**
         * Sets the email address.
         *
         * @param email the email address
         * @return this builder instance
         */
        public Builder email(String email) {
            this.email = email;
            return this;
        }

        /**
         * Sets whether the email is verified.
         *
         * @param emailVerified true if verified
         * @return this builder instance
         */
        public Builder emailVerified(Boolean emailVerified) {
            this.emailVerified = emailVerified;
            return this;
        }

        /**
         * Sets the gender.
         *
         * @param gender the gender
         * @return this builder instance
         */
        public Builder gender(String gender) {
            this.gender = gender;
            return this;
        }

        /**
         * Sets the birthdate.
         *
         * @param birthdate the birthdate
         * @return this builder instance
         */
        public Builder birthdate(String birthdate) {
            this.birthdate = birthdate;
            return this;
        }

        /**
         * Sets the time zone.
         *
         * @param zoneinfo the time zone
         * @return this builder instance
         */
        public Builder zoneinfo(String zoneinfo) {
            this.zoneinfo = zoneinfo;
            return this;
        }

        /**
         * Sets the locale.
         *
         * @param locale the locale
         * @return this builder instance
         */
        public Builder locale(String locale) {
            this.locale = locale;
            return this;
        }

        /**
         * Sets the phone number.
         *
         * @param phoneNumber the phone number
         * @return this builder instance
         */
        public Builder phoneNumber(String phoneNumber) {
            this.phoneNumber = phoneNumber;
            return this;
        }

        /**
         * Sets whether the phone number is verified.
         *
         * @param phoneNumberVerified true if verified
         * @return this builder instance
         */
        public Builder phoneNumberVerified(Boolean phoneNumberVerified) {
            this.phoneNumberVerified = phoneNumberVerified;
            return this;
        }

        /**
         * Sets the address.
         *
         * @param address the address
         * @return this builder instance
         */
        public Builder address(Address address) {
            this.address = address;
            return this;
        }

        /**
         * Sets the updated at timestamp.
         *
         * @param updatedAt the updated at timestamp
         * @return this builder instance
         */
        public Builder updatedAt(Long updatedAt) {
            this.updatedAt = updatedAt;
            return this;
        }

        /**
         * Sets additional claims.
         *
         * @param additionalClaims the additional claims map
         * @return this builder instance
         */
        public Builder additionalClaims(Map<String, Object> additionalClaims) {
            this.additionalClaims = additionalClaims;
            return this;
        }

        /**
         * Builds the {@link UserInfo}.
         *
         * @return the built user info
         * @throws IllegalStateException if sub is null
         */
        public UserInfo build() {
            if (ValidationUtils.isNullOrEmpty(sub)) {
                throw new IllegalStateException("sub (subject) is required");
            }
            return new UserInfo(this);
        }
    }

    /**
     * Represents a postal address.
     */
    public static class Address {
        private final String formatted;
        private final String streetAddress;
        private final String locality;
        private final String region;
        private final String postalCode;
        private final String country;

        public Address(String formatted, String streetAddress, String locality, 
                     String region, String postalCode, String country) {
            this.formatted = formatted;
            this.streetAddress = streetAddress;
            this.locality = locality;
            this.region = region;
            this.postalCode = postalCode;
            this.country = country;
        }

        public String getFormatted() {
            return formatted;
        }

        public String getStreetAddress() {
            return streetAddress;
        }

        public String getLocality() {
            return locality;
        }

        public String getRegion() {
            return region;
        }

        public String getPostalCode() {
            return postalCode;
        }

        public String getCountry() {
            return country;
        }
    }
}
