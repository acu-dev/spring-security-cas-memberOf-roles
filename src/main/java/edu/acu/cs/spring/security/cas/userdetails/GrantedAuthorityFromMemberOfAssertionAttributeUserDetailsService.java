/*
 * Copyright 2014 Abilene Christian University.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.acu.cs.spring.security.cas.userdetails;

import java.util.ArrayList;
import java.util.List;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Populates the {@link org.springframework.security.core.GrantedAuthority}s for a user by reading a
 * list of values from a memberOf attribute returned as part of the CAS response. Each value of the
 * attribute is turned into a GrantedAuthority by creating a new {@link javax.naming.ldap.LdapName}
 * and getting the last {@link javax.naming.ldap.Rdn} value.
 * <p>
 * For example, "CN=SSO_ADMIN,OU=roles,DC=spring,DC=io" would be converted to a new
 * {@link org.springframework.security.core.GrantedAuthority}("SSO_ADMIN")
 *
 * @author Harvey McQueen
 */
public class GrantedAuthorityFromMemberOfAssertionAttributeUserDetailsService extends AbstractCasAssertionUserDetailsService {

    private static final Log logger = LogFactory.getLog(GrantedAuthorityFromMemberOfAssertionAttributeUserDetailsService.class);

    private static final String NON_EXISTENT_PASSWORD_VALUE = "NO_PASSWORD";
    private static final String DEFAULT_ATTRIBUTE = "memberOf";
    private static final String DEFAULT_ROLE_PREFIX = "ROLE_";

    private String attribute = DEFAULT_ATTRIBUTE;
    private String rolePrefix = DEFAULT_ROLE_PREFIX;
    private boolean convertToUpperCase = true;
    private boolean convertSpacesToUnderscores = true;

    @Override
    protected UserDetails loadUserDetails(Assertion assertion) {
        final List<GrantedAuthority> grantedAuthorities = new ArrayList<>();

        final Object value = assertion.getPrincipal().getAttributes().get(attribute);

        if (value != null) {
            if (value instanceof List) {
                final List list = (List) value;

                for (final Object o : list) {
                    convertObjectAndAddGrantedAuthorityToList(o, grantedAuthorities);
                }
            } else {
                convertObjectAndAddGrantedAuthorityToList(value, grantedAuthorities);
            }
        }

        return new User(assertion.getPrincipal().getName(), NON_EXISTENT_PASSWORD_VALUE, true, true, true, true, grantedAuthorities);
    }

    private void convertObjectAndAddGrantedAuthorityToList(final Object o, final List<GrantedAuthority> grantedAuthorities) {
        if (o instanceof String) {
            final String memberOfString = (String) o;
            try {
                LdapName name = new LdapName(memberOfString);
                if (name.size() > 0) {
                    String value = name.getRdn(name.size() - 1).getValue().toString();
                    if (this.convertToUpperCase) {
                        value = value.toUpperCase();
                    }
                    if (this.convertSpacesToUnderscores) {
                        value = value.replace(' ', '_');
                    }
                    grantedAuthorities.add(new SimpleGrantedAuthority(rolePrefix + value));
                }
            } catch (InvalidNameException e) {
                logger.warn("Couldn't convert \"" + memberOfString + "\" to an LdapName", e);
            }
        }
    }

    /**
     * Sets the attribute value to be retrieved.
     *
     * @param attribute
     */
    public void setAttribute(final String attribute) {
        this.attribute = attribute;
    }
    
    /**
     * Sets the role prefix to be used in creating every {@link org.springframework.security.core.GrantedAuthority}.
     *
     * @param rolePrefix
     */
    public void setRolePrefix(final String rolePrefix) {
        this.rolePrefix = rolePrefix;
    }

    /**
     * Enables/Disables conversion of the returned attribute values to uppercase values.
     *
     * @param convertToUpperCase true if it should convert, false otherwise. Default true.
     */
    public void setConvertToUpperCase(final boolean convertToUpperCase) {
        this.convertToUpperCase = convertToUpperCase;
    }

    /**
     * Enables/Disables conversion of spaces in the returned attribute values to underscores.
     *
     * @param convertSpacesToUnderscores true if it should convert, false otherwise. Default true.
     */
    public void setConvertSpacesToUnderscores(final boolean convertSpacesToUnderscores) {
        this.convertSpacesToUnderscores = convertSpacesToUnderscores;
    }

}
