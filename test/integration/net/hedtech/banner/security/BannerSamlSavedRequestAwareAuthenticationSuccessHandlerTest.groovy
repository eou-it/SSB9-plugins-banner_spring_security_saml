/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
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

    BannerAuthenticationProvider bannerAuthenticationProvider
    public static final String EDITABLE_USER = "GRAILS_USER"
    def BannerSamlSessionRegistryImpl sessionRegistry;
    MockHttpServletRequest request;
    MockHttpServletResponse response;
    MockHttpSession session;
    BannerSamlSavedRequestAwareAuthenticationSuccessHandler bannerSamlSavedRequestAwareAuthenticationSuccessHandler;
    BannerAuthenticationToken authenticationToken;
    BannerUser bannerUser;

    def dataSource


    @Before
    public void setup() {

        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        session = new MockHttpSession();
        sessionRegistry=new BannerSamlSessionRegistryImpl();
        bannerAuthenticationProvider.dataSource=this.dataSource
        Authentication auth = bannerAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(EDITABLE_USER,"u_pick_it"));

        Map authenticationResults = [ name:           auth.name,
                                      credentials:    auth.credentials,
                                      oracleUserName: auth.name,
                                      valid:          true ].withDefault { k -> false }

        def s = BannerGrantedAuthorityService.determineAuthorities(authenticationResults, dataSource)

        //assertNotNull(s);
        bannerUser = new BannerUser("PTHOMAS","U_PICK_IT","PTHOMAS", true, false, false, false, s, "MohitJain");
        authenticationToken=new BannerAuthenticationToken(bannerUser,null);
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
