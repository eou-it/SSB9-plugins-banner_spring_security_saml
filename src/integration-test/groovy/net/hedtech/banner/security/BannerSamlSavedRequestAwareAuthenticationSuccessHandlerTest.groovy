/*******************************************************************************
 Copyright 2015 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import net.hedtech.banner.security.*
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication

class BannerSamlSavedRequestAwareAuthenticationSuccessHandlerTest extends Assert {

    def BannerSamlSessionRegistryImpl sessionRegistry;
    MockHttpServletRequest request;
    MockHttpServletResponse response;
    MockHttpSession session;
    BannerSamlSavedRequestAwareAuthenticationSuccessHandler bannerSamlSavedRequestAwareAuthenticationSuccessHandler;
    BannerAuthenticationToken authenticationToken;

    @Before
    public void setup() {

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        session = new MockHttpSession();
        sessionRegistry=new BannerSamlSessionRegistryImpl();
        authenticationToken=new BannerAuthenticationToken(null,null);
        bannerSamlSavedRequestAwareAuthenticationSuccessHandler= new BannerSamlSavedRequestAwareAuthenticationSuccessHandler();
    }


    @Test
    public void testSuccessHandler(){
        authenticationToken.sessionIndex="dsfsd909d0fd90fd09d09fdfd";
        request.setSession(session);
        bannerSamlSavedRequestAwareAuthenticationSuccessHandler.sessionRegistry=sessionRegistry;
        bannerSamlSavedRequestAwareAuthenticationSuccessHandler.onAuthenticationSuccess(request,response,authenticationToken)
        assertEquals(response.getStatus(),302);
    }




}
