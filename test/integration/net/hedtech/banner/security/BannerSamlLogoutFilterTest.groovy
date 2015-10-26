/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import net.hedtech.banner.testing.BaseIntegrationTestCase
import org.codehaus.groovy.runtime.typehandling.GroovyCastException
import org.joda.time.DateTime
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.opensaml.Configuration
import org.opensaml.common.SAMLObjectBuilder
import org.opensaml.common.SAMLVersion
import org.opensaml.saml2.core.*
import org.opensaml.saml2.metadata.Endpoint
import org.opensaml.saml2.metadata.EntityDescriptor
import org.opensaml.saml2.metadata.SPSSODescriptor
import org.opensaml.saml2.metadata.impl.SingleSignOnServiceImpl
import org.opensaml.saml2.metadata.provider.MetadataProviderException
import org.opensaml.ws.message.encoder.MessageEncodingException
import org.opensaml.xml.XMLObjectBuilderFactory
import org.opensaml.xml.schema.XSString
import org.opensaml.xml.schema.impl.XSStringBuilder
import org.springframework.context.ApplicationContext
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.saml.SAMLAuthenticationToken
import org.springframework.security.saml.SAMLConstants
import org.springframework.security.saml.context.SAMLContextProvider
import org.springframework.security.saml.context.SAMLMessageContext
import org.springframework.security.saml.metadata.ExtendedMetadata
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
import static org.easymock.EasyMock.replay
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotNull

class BannerSamlLogoutFilterTest extends BaseIntegrationTestCase {

    def dataSource

    BannerSamlAuthenticationProvider bannerSamlAuthenticationProvider
    WebSSOProfileConsumer consumer
    NameID nameID
    Assertion assertion
    SAMLMessageStorage messageStorage
    ApplicationContext context
    SAMLMessageContext messageContext
    XMLObjectBuilderFactory builderFactory
    ExtendedMetadata peerExtendedMetadata;
    MetadataManager metadata;
    BannerSamlLogoutFilter filter;
    def SAMLContextProvider contextProvider;
    def SingleLogoutProfile profile
    SAMLProcessor samlProcessor

    MockHttpServletRequest request;
    MockHttpServletResponse response;
    MockFilterChain chain;

    private LogoutHandler[] handlers;



    @Before
    public void setUp() {
        bannerSamlAuthenticationProvider = new BannerSamlAuthenticationProvider()
        bannerSamlAuthenticationProvider.dataSource = this.dataSource
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        chain= new MockFilterChain();
        handlers =  new SecurityContextLogoutHandler() ;
        filter = new BannerSamlLogoutFilter("/logout", handlers, handlers);
        profile= new SingleLogoutProfileImpl();
        samlProcessor= createMock(SAMLProcessorImpl.class);
        profile.setProcessor(samlProcessor);
        filter.setProfile(profile)

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
        filter.processLogout(request, response,chain)
        assertEquals(response.getStatus(),302);

    }

    @Test
    public void "Validate Global logout fails if local = true in request"() {

        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = initialize("9BE22914996B2516E040007F01006516",false);
        authentication = (BannerAuthenticationToken)bannerSamlAuthenticationProvider.authenticate(token)
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local","true")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response,chain)
        assertEquals(response.getStatus(),302);


    }

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();


    @Test
    public void " Validate Global logout pass if local = false in request"() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = initialize("9BE22914996B2516E040007F01006516",false);
        authentication = (BannerAuthenticationToken)bannerSamlAuthenticationProvider.authenticate(token)
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local","false")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response,chain)
        assertEquals(response.getStatus(),200);

    }

    @Test
    public void " Validate Global logout fails if no parameter in request called local"() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = initialize("9BE22914996B2516E040007F01006516",false);
        authentication = (BannerAuthenticationToken)bannerSamlAuthenticationProvider.authenticate(token)
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        //request.setParameter("local","false")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response,chain)
        assertEquals(response.getStatus(),200);
    }

    @Test
    public void " verify local logout clears the http session"() {

        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = initialize("9BE22914996B2516E040007F01006516",false);
        authentication = (BannerAuthenticationToken)bannerSamlAuthenticationProvider.authenticate(token)
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local","true")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        assertEquals(request.getSession(true).getId(),session.getId());
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response,chain)
        assertNotEquals(request.getSession(true).getId(),session.getId());
    }

    @Test
    public void " verify if auth getSAMLCredential is empty"() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = initialize("9BE22914996B2516E040007F01006516",false);
        authentication = (BannerAuthenticationToken)bannerSamlAuthenticationProvider.authenticate(token)
        authentication.SAMLCredential=null;
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local","false")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response,chain)
        assertEquals(response.getStatus(),302);
    }

    /**
     * Verifies that user details are filled correctly if set and that entitlements of the user returned from
     * the userDetails are set to the authentication object.
     *
     * @throws Exception error
     */
    @Test
    public void " Validate ProcessLogout  with auth object not of type BannerAuthenticationToken "() throws  Exception {
        expectedEx.expect(GroovyCastException.class);
        SAMLAuthenticationToken token = initialize("9BE22914996B2516E040007F01006516",false);
        Authentication authentication = new SAMLAuthenticationToken(token.getCredentials());
        authentication.credentials=token.getCredentials();
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local","false")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response,chain)
    }

    @Test
    public void " Message Encoding Exception"() {
        expectedEx.expect(AuthenticationServiceException.class);
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = initialize("9BE22914996B2516E040007F01006516",true);
        authentication = (BannerAuthenticationToken)bannerSamlAuthenticationProvider.authenticate(token)
        assertNotNull(authentication)
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);

        request.setParameter("local","false")
        request.setRequestURI("/saml/logout");

        // Create a new session and add the security context.
        HttpSession session = request.getSession(true);
        session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);
        filter.setContextProvider(contextProvider);
        filter.processLogout(request, response,chain)
    }



    private void replayMock() {

        replay(messageStorage);
        replay(nameID);
        replay(assertion);
    }

    public SAMLAuthenticationToken initialize(String UdcID,boolean issuerFlag) {
        bannerSamlAuthenticationProvider = new BannerSamlAuthenticationProvider()
        bannerSamlAuthenticationProvider.dataSource = dataSource
        bannerSamlAuthenticationProvider.setForcePrincipalAsString(false)

        consumer = new WebSSOProfileConsumerImpl()
        nameID = createMock(NameID.class)
        assertion = createMock(Assertion.class)
        messageStorage = createMock(SAMLMessageStorage.class)

        bannerSamlAuthenticationProvider.setConsumer(consumer);

        builderFactory = Configuration.getBuilderFactory()
        SAMLObjectBuilder<Response> builder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = builder.buildObject();
        response.setIssueInstant(new DateTime());
        response.setInResponseTo(generateId());

        StatusCode statusCode = ((SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME)).buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        Status status = ((SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME)).buildObject();
        status.setStatusCode(statusCode);
        response.setStatus(status);

        Assertion assertion=buildAssertion(UdcID,issuerFlag)
        response.getAssertions().add(assertion);
        messageContext = new SAMLMessageContext();
        messageContext.setInboundSAMLMessage(response)

        messageContext.peerEntityMetadata = ((SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME)).buildObject()
        messageContext.peerEntityMetadata.entityID = "localhost:default:entityId"

        SPSSODescriptor localEntityRoleMetadata = ((SAMLObjectBuilder<SPSSODescriptor>) builderFactory.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME)).buildObject()
        localEntityRoleMetadata.wantAssertionsSigned = false
        messageContext.localEntityRoleMetadata = localEntityRoleMetadata

        messageContext.setCommunicationProfileId(SAMLConstants.SAML2_WEBSSO_PROFILE_URI)

        Endpoint samlEndpoint = new SingleSignOnServiceImpl("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "UDC_IDENTIFIER", "name")
        samlEndpoint.setLocation("http://localhost")
        messageContext.localEntityEndpoint = samlEndpoint

        messageContext.localEntityId = "test"  // should match Audience.uri

        ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(messageContext.getPeerEntityMetadata().getEntityID());
        messageContext.setPeerExtendedMetadata(extendedMetadata);


        messageContext.peerExtendedMetadata.supportUnsolicitedResponse=true;
        SAMLAuthenticationToken token = new SAMLAuthenticationToken(messageContext)

        replayMock();

        return token

    }
    public final Assertion buildAssertion(String UdcID,boolean issuerFlag) throws IllegalStateException {
        AuthnContextClassRef authnContextClassRef = ((SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
                .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME))
                .buildObject();
        authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        AuthnContext authnContext = ((SAMLObjectBuilder<AuthnContext>) builderFactory
                .getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME)).buildObject();
        authnContext.setAuthnContextClassRef(authnContextClassRef);

        AuthnStatement authStatement = ((SAMLObjectBuilder<AuthnStatement>) builderFactory
                .getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME)).buildObject();
        authStatement.setAuthnContext(authnContext);
        authStatement.setAuthnInstant(new DateTime());


        Conditions conditions = ((SAMLObjectBuilder<Conditions>) builderFactory
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME)).buildObject();
        conditions.setNotBefore(new DateTime());
        conditions.setNotOnOrAfter(new DateTime()
                .plusSeconds(120));

        Audience audience=((SAMLObjectBuilder<Audience>) builderFactory
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME)).buildObject()
        audience.setAudienceURI("test");

        AudienceRestriction audienceRestrictions=((SAMLObjectBuilder<AudienceRestriction>) builderFactory
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME)).buildObject()
        audienceRestrictions.getAudiences().add(audience);

        conditions.getAudienceRestrictions().add(audienceRestrictions);

        Issuer issuer = ((SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
        if(issuerFlag){
            issuer.setValue("abc");
        }else{
            issuer.setValue("localhost:default:entityId");
        }

        Assertion assertion = ((SAMLObjectBuilder<Assertion>) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME)).buildObject();
        assertion.setIssuer(issuer);

        assertion.setIssueInstant(new DateTime());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setID(generateId());
        assertion.getAuthnStatements().add(authStatement);
        assertion.setConditions(conditions);
        assertion.setSubject(buildSubject());

        AttributeStatement attributeStatement = buildAttributeStatement(UdcID);
        if (attributeStatement != null) {
            assertion.getAttributeStatements().add(attributeStatement);
        }
        return assertion;
    }

    private Subject buildSubject() {
        NameID nameId = ((SAMLObjectBuilder<NameID>) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
        nameId.setValue("TEST");


        SubjectConfirmationData subjectConfirmationData = ((SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
                .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME))
                .buildObject();
        subjectConfirmationData.setNotOnOrAfter(new DateTime()
                .plusSeconds(120))
        subjectConfirmationData.setRecipient("http://localhost")

        SubjectConfirmation subjectConfirmation = ((SAMLObjectBuilder<SubjectConfirmation>) builderFactory
                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME))
                .buildObject();
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer")

        Subject subject = ((SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME)).buildObject();
        subject.setNameID(nameId);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        return subject;
    }
    protected String generateId(){
        String id = "_" + Integer.toHexString(new Random().nextInt(Integer.MAX_VALUE)) + "-" + Integer.toHexString(new Random().nextInt(Integer.MAX_VALUE));
        return id;
    }

    protected AttributeStatement buildAttributeStatement(String UdcID) throws IllegalStateException {

        AttributeStatement attributeStatement = ((SAMLObjectBuilder<AttributeStatement>) builderFactory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME))
                .buildObject();

        XSString udcIDAttributeValue = ((XSStringBuilder) Configuration
                .getBuilderFactory().getBuilder(XSString.TYPE_NAME))
                .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                XSString.TYPE_NAME);
        udcIDAttributeValue.setValue(UdcID);

        Attribute udcIdAttribute = ((SAMLObjectBuilder<Attribute>) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME)).buildObject();
        udcIdAttribute.setName("UDC_IDENTIFIER");
        udcIdAttribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
        udcIdAttribute.getAttributeValues().add( udcIDAttributeValue);

        attributeStatement.getAttributes().add(udcIdAttribute);

        attributeStatement

    }

}
