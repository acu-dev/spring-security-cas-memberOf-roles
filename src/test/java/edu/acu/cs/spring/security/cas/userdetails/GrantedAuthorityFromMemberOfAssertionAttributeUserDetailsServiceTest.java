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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.validation.Assertion;
import org.junit.Test;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 *
 * @author Harvey McQueen
 */
public class GrantedAuthorityFromMemberOfAssertionAttributeUserDetailsServiceTest {

    @Test
    public void correctlyExtractsNamedAttributeFromAssertionAndConvertsThemToAuthorities() {
        GrantedAuthorityFromMemberOfAssertionAttributeUserDetailsService uds
                = new GrantedAuthorityFromMemberOfAssertionAttributeUserDetailsService();
        uds.setConvertToUpperCase(false);
        uds.setConvertSpacesToUnderscores(false);
        uds.setAttribute("a");
        uds.setRolePrefix("");
        Assertion assertion = mock(Assertion.class);
        AttributePrincipal principal = mock(AttributePrincipal.class);
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("a", Arrays.asList("CN=role_a1,OU=roles,DC=spring,DC=io", "CN=role_a2,OU=roles,DC=spring,DC=io"));
        attributes.put("b", "b");
        attributes.put("c", "c");
        attributes.put("d", null);
        attributes.put("someother", "unused");
        when(assertion.getPrincipal()).thenReturn(principal);
        when(principal.getAttributes()).thenReturn(attributes);
        when(principal.getName()).thenReturn("somebody");
        CasAssertionAuthenticationToken token = new CasAssertionAuthenticationToken(assertion, "ticket");
        UserDetails user = uds.loadUserDetails(token);
        Set<String> roles = AuthorityUtils.authorityListToSet(user.getAuthorities());
        assertTrue(roles.size() == 2);
        assertTrue(roles.contains("role_a1"));
        assertTrue(roles.contains("role_a2"));
    }

    @Test
    public void correctlyExtractsDefaultNamedAttributeFromAssertionAndConvertsThemToAuthorities() {
        GrantedAuthorityFromMemberOfAssertionAttributeUserDetailsService uds
                = new GrantedAuthorityFromMemberOfAssertionAttributeUserDetailsService();
        Assertion assertion = mock(Assertion.class);
        AttributePrincipal principal = mock(AttributePrincipal.class);
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("memberOf", Arrays.asList("CN=a1,ou=other,OU=roles,DC=spring,DC=io", "CN=a2,OU=roles,dc=spring,DC=io", null));
        attributes.put("someother", "unused");
        when(assertion.getPrincipal()).thenReturn(principal);
        when(principal.getAttributes()).thenReturn(attributes);
        when(principal.getName()).thenReturn("somebody");
        CasAssertionAuthenticationToken token = new CasAssertionAuthenticationToken(assertion, "ticket");
        UserDetails user = uds.loadUserDetails(token);
        Set<String> roles = AuthorityUtils.authorityListToSet(user.getAuthorities());
        assertTrue(roles.size() == 2);
        assertTrue(roles.contains("ROLE_A1"));
        assertTrue(roles.contains("ROLE_A2"));
    }
}
