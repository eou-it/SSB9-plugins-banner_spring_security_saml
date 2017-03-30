/** *****************************************************************************
 © 2017 SunGard Higher Education.  All Rights Reserved.

 CONFIDENTIAL BUSINESS INFORMATION

 THIS PROGRAM IS PROPRIETARY INFORMATION OF SUNGARD HIGHER EDUCATION
 AND IS NOT TO BE COPIED, REPRODUCED, LENT, OR DISPOSED OF,
 NOR USED FOR ANY PURPOSE OTHER THAN THAT WHICH IT IS SPECIFICALLY PROVIDED
 WITHOUT THE WRITTEN PERMISSION OF THE SAID COMPANY
 ****************************************************************************** */
package net.hedtech.banner.security

import grails.util.Holders
import net.hedtech.banner.testing.BaseIntegrationTestCase
import org.codehaus.groovy.grails.plugins.testing.GrailsMockHttpServletRequest
import org.codehaus.groovy.grails.plugins.testing.GrailsMockHttpServletResponse
import org.easymock.EasyMock
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.RedirectStrategy
import org.springframework.security.web.WebAttributes

/**
 * BannerSamlAuthenticationFailureHandlerIntegrationTests.
 *
 * Date: 3/28/2017
 * Time: 4:58 PM
 */
class BannerSamlAuthenticationFailureHandlerIntegrationTests extends BaseIntegrationTestCase {
    BannerSamlAuthenticationFailureHandler bannerSamlAuthenticationFailureHandler
    GrailsMockHttpServletRequest request
    GrailsMockHttpServletResponse response
    AuthenticationException e

    @Before
    public void setUp() {
        Holders?.config.banner.sso.authenticationAssertionAttribute = "UDC_IDENTIFIER"
        formContext = ['GUAGMNU']
        bannerSamlAuthenticationFailureHandler = new BannerSamlAuthenticationFailureHandler()
        request = new GrailsMockHttpServletRequest()
        response = new GrailsMockHttpServletResponse()
        e = EasyMock.createMock(AuthenticationException.class)
        super.setUp()
    }

    @After
    public void tearDown() {
        super.tearDown()
    }

    @Test
    public void error401IsReturnedIfNoUrlIsSet() throws Exception {
        RedirectStrategy rs = EasyMock.createMock(RedirectStrategy.class)
        bannerSamlAuthenticationFailureHandler.setRedirectStrategy(rs)
        assert (bannerSamlAuthenticationFailureHandler.getRedirectStrategy() == rs)

        bannerSamlAuthenticationFailureHandler.onAuthenticationFailure(request, response, e)
        assert (response.getStatus() == 401)
    }

    @Test
    public void exceptionIsSavedToSessionOnRedirect() throws Exception {
        bannerSamlAuthenticationFailureHandler.setDefaultFailureUrl("/target")

        bannerSamlAuthenticationFailureHandler.onAuthenticationFailure(request, response, e)
        assert (request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) == e)
        assert (response.getRedirectedUrl() == "/target")
    }

    @Test
    public void responseIsForwardedIfUseForwardIsTrue() throws Exception {
        BannerSamlAuthenticationFailureHandler bsafh = new BannerSamlAuthenticationFailureHandler()
        bsafh.setDefaultFailureUrl("/target")
        bsafh.setUseForward(true)
        assertTrue(bsafh.isUseForward())

        bsafh.onAuthenticationFailure(request, response, e)
        assertNull(response.getRedirectedUrl())
        assertEquals(response.getForwardedUrl(), "/target")

        // Request scope should be used for forward
        assertSame(request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION), e)
    }
}
