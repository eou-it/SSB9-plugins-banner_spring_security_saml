/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import net.hedtech.banner.security.BannerSamlLogoutFilter
import org.junit.Before
import org.junit.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;


import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull

class BannerSamlLogoutFilterTest {

    BannerSamlLogoutFilter filter;

    MockHttpServletRequest request;
    MockHttpServletResponse response;

    private LogoutHandler[] handlers;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        handlers =  new SecurityContextLogoutHandler() ;
        filter = new BannerSamlLogoutFilter("/logout", handlers, handlers);
    }
    @Test
    public void requiresLogout() {
        assertEquals(false, filter.requiresLogout(request, response));

        request.setRequestURI("/logout");

        assertEquals(false, filter.requiresLogout(request, response));
    }

    @Test
    public void constructorStringLogoutHandlersLogoutHandlersNotNullFilterProcessUrl() {
        assertNotNull(filter.getFilterProcessesUrl());
    }

    @Test
    public void constructorLogoutSuccessHandlerLogoutHandlersLogoutHandlersNotNullFilterProcessUrl() {
        filter = new BannerSamlLogoutFilter(new SimpleUrlLogoutSuccessHandler(), handlers, handlers);
        assertNotNull(filter.getFilterProcessesUrl());
    }

}
