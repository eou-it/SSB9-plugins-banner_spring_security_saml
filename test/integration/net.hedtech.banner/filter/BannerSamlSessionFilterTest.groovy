/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.filter

import net.hedtech.banner.security.BannerSamlSessionFilter
import net.hedtech.banner.security.BannerSamlSessionRegistryImpl
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.opensaml.common.SAMLRuntimeException
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.saml.context.SAMLContextProvider
import org.springframework.security.saml.processor.SAMLProcessor

import static org.junit.Assert.assertEquals

class BannerSamlSessionFilterTest {

    def BannerSamlSessionFilter filterUnderTest;
    def BannerSamlSessionRegistryImpl sessionRegistry;
    def SAMLContextProvider contextProvider;
    def SAMLProcessor processor;
    MockHttpServletRequest request;
    MockHttpServletResponse response;
    MockFilterChain mockChain;
    MockHttpSession session;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        mockChain = new MockFilterChain();
        session = new MockHttpSession();
        filterUnderTest = new BannerSamlSessionFilter();
        sessionRegistry=new BannerSamlSessionRegistryImpl();
    }


    @Test
    public void testDoFilterIfSessionIsNull() {
        session=null;
        request.setSession(session);
        request.setRequestURI("/saml/logout");
        filterUnderTest.doFilter(request, response, mockChain);
        assertEquals(response.getStatus(),200);

    }

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Test
    public void testDoFilterIfSessionIsNullAndFilterURLIsDifferent() {
        expectedEx.expect(SAMLRuntimeException.class);
        expectedEx.expectMessage("Incoming SAML message is invalid");
        session=null;
        request.setSession(session);
        request.setRequestURI("/saml/SingleLogout");
        filterUnderTest.setSessionRegistry(sessionRegistry);
        filterUnderTest.setContextProvider(contextProvider);
        filterUnderTest.setSAMLProcessor(processor);
        filterUnderTest.doFilter(request, response, mockChain);
        assertEquals(response.getStatus(),200);

    }

    @Test
    public void testDoFilterIfSessionIsNotNull() {
        request.setSession(session);
        request.setRequestURI("/saml/logout");
        filterUnderTest.setSessionRegistry(sessionRegistry)
        filterUnderTest.doFilter(request, response, mockChain);
        assertEquals(response.getStatus(),200);

    }




}
