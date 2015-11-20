/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import net.hedtech.banner.testing.BaseIntegrationTestCase
import org.codehaus.groovy.runtime.typehandling.GroovyCastException
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.opensaml.Configuration
import org.opensaml.saml2.core.Assertion
import org.opensaml.saml2.core.NameID
import org.opensaml.saml2.metadata.provider.MetadataProviderException
import org.opensaml.xml.XMLObjectBuilderFactory
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.saml.SAMLAuthenticationToken
import org.springframework.security.saml.context.SAMLContextProvider
import org.springframework.security.saml.metadata.MetadataManager
import org.springframework.security.saml.processor.SAMLProcessor
import org.springframework.security.saml.processor.SAMLProcessorImpl
import org.springframework.security.saml.storage.SAMLMessageStorage
import org.springframework.security.saml.websso.SingleLogoutProfile
import org.springframework.security.saml.websso.SingleLogoutProfileImpl
import org.springframework.security.saml.websso.WebSSOProfileConsumer
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler

import javax.servlet.http.HttpSession

import static org.easymock.EasyMock.createMock
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull

class BannerSamlLogoutFilterTest extends BaseIntegrationTestCase {

    def dataSource
    MetadataManager metadata;
    BannerSamlAuthenticationProvider bannerSamlAuthenticationProvider
    WebSSOProfileConsumer consumer
    NameID nameID
    Assertion assertion
    SAMLMessageStorage messageStorage
    XMLObjectBuilderFactory builderFactory
    BannerSamlLogoutFilter filter;
    def SAMLContextProvider contextProvider;
    def SingleLogoutProfile profile
    SAMLProcessor samlProcessor
    BannerSamlUtility bannerSamlUtility

    MockHttpServletRequest request;
    MockHttpServletResponse response;
    MockFilterChain chain;

    private LogoutHandler[] handlers;


    @Before
    public void setUp() {
        consumer = new WebSSOProfileConsumerImpl()
        nameID = createMock(NameID.class)
        assertion = createMock(Assertion.class)
        messageStorage = createMock(SAMLMessageStorage.class)
        builderFactory = Configuration.getBuilderFactory()
        bannerSamlUtility = new BannerSamlUtility();
        bannerSamlUtility.messageStorage = messageStorage;
        bannerSamlUtility.nameID = nameID;
        bannerSamlUtility.assertionobj = assertion;
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
        handlers = new SecurityContextLogoutHandler();
        profile = new SingleLogoutProfileImpl();
        samlProcessor = createMock(SAMLProcessorImpl.class);
        profile.setProcessor(samlProcessor);
        filter = new BannerSamlLogoutFilter("/logout", handlers, handlers);
        filter.setProfile(profile)
        bannerSamlAuthenticationProvider = new BannerSamlAuthenticationProvider()
        bannerSamlAuthenticationProvider.dataSource = this.dataSource
        bannerSamlAuthenticationProvider.setForcePrincipalAsString(false)
        bannerSamlAuthenticationProvider.setConsumer(consumer);
    }

    @After
    public void tearDown() {
        logout()
    }

    @Test
    public void "validate different URL to see if requiresLogout returns false "() {
        assertEquals(false, filter.requiresLogout(request, response));
    }

    @Test
    public void "validate different URL to see if requiresLogout returns true"() {
        request.setRequestURI("/saml/logout");
        assertEquals(true, filter.requiresLogout(request, response));
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

    @Test
    public void "Validate ProcessLogout with auth null"() {
        request.setRequestURI("/saml/logout");
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(null);

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response, chain)
        assertEquals(response.getStatus(), 302);

    }

    @Test
    public void "Validate Global logout fails if local = true in request"() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize("9BE22914996B2516E040007F01006516", false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local", "true")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response, chain)
        assertEquals(response.getStatus(), 302);


    }

    @Test
    public void "validation isGlobalLogout "() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize("9BE22914996B2516E040007F01006516", false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        request.setParameter("local", "false");
        assertTrue(filter.isGlobalLogout(request, authentication))

    }

    @Test
    public void "validation isLocalLogout "() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize("9BE22914996B2516E040007F01006516", false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        request.setParameter("local", "true");
        assertFalse(filter.isGlobalLogout(request, authentication))

    }

    @Test
    public void "validation isGlobalLogout with no local parameter "() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize("9BE22914996B2516E040007F01006516", false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        assertTrue(filter.isGlobalLogout(request, authentication))

    }

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();


    @Test
    public void " Validate Global logout pass if local = false in request"() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize("9BE22914996B2516E040007F01006516", false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local", "false")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response, chain)
        assertEquals(response.getStatus(), 200);

    }


    @Test
    public void " verify local logout clears the http session"() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize("9BE22914996B2516E040007F01006516", false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local", "true")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        assertEquals(request.getSession(true).getId(), session.getId());
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response, chain)
        assertNotEquals(request.getSession(true).getId(), session.getId());
    }

    @Test
    public void " verify if auth getSAMLCredential is empty"() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize("9BE22914996B2516E040007F01006516", false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        authentication.SAMLCredential = null;
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local", "false")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response, chain)
        assertEquals(response.getStatus(), 302);
    }

    /**
     * Verifies that user details are filled correctly if set and that entitlements of the user returned from
     * the userDetails are set to the authentication object.
     *
     * @throws Exception error
     */
    @Test
    public void " Validate ProcessLogout  with auth object not of type BannerAuthenticationToken "() throws Exception {
        expectedEx.expect(GroovyCastException.class);
        SAMLAuthenticationToken token = bannerSamlUtility.initialize("9BE22914996B2516E040007F01006516", false, builderFactory, metadata);
        Authentication authentication = new SAMLAuthenticationToken(token.getCredentials());
        authentication.credentials = token.getCredentials();
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local", "false")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response, chain)
    }

    @Test
    public void " Message Encoding Exception"() {
        expectedEx.expect(AuthenticationServiceException.class);
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize("9BE22914996B2516E040007F01006516", true, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local", "false")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response, chain)
    }
}
