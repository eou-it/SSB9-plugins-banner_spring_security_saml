/*******************************************************************************
 Copyright 2015-2017 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import grails.spring.BeanBuilder
import grails.util.Holders
import net.hedtech.banner.testing.BaseIntegrationTestCase
import org.apache.commons.dbcp.BasicDataSource
import org.joda.time.DateTime
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.opensaml.Configuration
import org.opensaml.common.SAMLObjectBuilder
import org.opensaml.common.SAMLVersion
import org.opensaml.saml2.core.*
import org.opensaml.saml2.metadata.Endpoint
import org.opensaml.saml2.metadata.EntityDescriptor
import org.opensaml.saml2.metadata.SPSSODescriptor
import org.opensaml.saml2.metadata.impl.SingleSignOnServiceImpl
import org.opensaml.xml.XMLObjectBuilderFactory
import org.opensaml.xml.schema.XSString
import org.opensaml.xml.schema.impl.XSStringBuilder
import org.springframework.context.ApplicationContext
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.saml.SAMLAuthenticationToken
import org.springframework.security.saml.SAMLConstants
import org.springframework.security.saml.context.SAMLMessageContext
import org.springframework.security.saml.metadata.ExtendedMetadata
import org.springframework.security.saml.metadata.MetadataManager
import org.springframework.security.saml.storage.SAMLMessageStorage
import org.springframework.security.saml.websso.WebSSOProfileConsumer
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl

import static org.easymock.EasyMock.createMock
import static org.easymock.EasyMock.replay

class BannerSamlAuthenticationProviderTests extends BaseIntegrationTestCase {

    public static final String UDC_ID_TEST = 'INTEGRATION_TEST_SAML'
    public static final String USER_NAME_TEST = 'GRAILS_USER'
    public static final String UDC_ID_TEST_DISABLED = 'INTEGRATION_TEST_SAML_DISABLED'


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




    @Before
    public void setUp() {
        bannerSamlAuthenticationProvider = new BannerSamlAuthenticationProvider()
        bannerSamlAuthenticationProvider.dataSource = this.dataSource
    }
    @After
    public void tearDown() {

        logout()
    }

    /**
     * Verify that authentication does not process if the SAMLAuthenticationToken is not passed
     *
     * @throws IllegalArgumentException IllegalArgumentException
     */
    @Test(expected = IllegalArgumentException.class)
    void testAdminDoFilter() {
        Authentication auth = new UsernamePasswordAuthenticationToken("user", "pass")
        bannerSamlAuthenticationProvider.authenticate(auth);
    }

    /**
     * Verifies that authentication process fails when UDC_IDENTIFIER is null
     *
     * @throws Exception error
     */
    @Test
    public void testAuthenticateFailure() throws Exception {

        SAMLAuthenticationToken token = initialize("")
        try {
            bannerSamlAuthenticationProvider.authenticate(token);
        }catch(Exception e) {
            assertEquals("System is configured for SAML authentication and identity assertion UDC_IDENTIFIER is null", e.message)
        }

    }

    /**
     * Verifies that authentication process passes successfully if UDC_IDENTIFIER passed is correct.
     *
     * @throws Exception error
     */
    @Test
    public void testAuthenticateOracleUser() {
        /*def user = getOracleUser()*/

        SAMLAuthenticationToken token = initialize(UDC_ID_TEST)
        Authentication authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token);

        assertEquals(authentication.oracleUserName, USER_NAME_TEST)
    }

    /**
     * Verifies that authentication process fails if UDC_IDENTIFIER passed does not map to any Banner user.
     *
     * @throws Exception error
     */
    @Test
    public void testAuthenticateNoBannerUser() {
        SAMLAuthenticationToken token = initialize("2")
        try {
            Authentication authentication = bannerSamlAuthenticationProvider.authenticate(token);
        }
        catch (Exception e) {
            assertTrue e instanceof BadCredentialsException
            assertEquals("", e.message)
        }


    }

    /**
     * Verifies that authentication process passes successfully if UDC_IDENTIFIER passed maps to a SSB user & no oracle user.
     *
     * @throws Exception error
     */
    @Test
    public void testAuthenticateSSBUser() {

        Holders?.config.ssbEnabled = true

        ApplicationContext testSpringContext = createUnderlyingSsbDataSourceBean()
        dataSource.underlyingSsbDataSource =  testSpringContext.getBean("underlyingSsbDataSource")

        bannerSamlAuthenticationProvider.dataSource = this.dataSource

        // def bannerPidm = generatePidm()
        //def udc_id = createUdcID(bannerPidm)

        Authentication authentication
        SAMLAuthenticationToken token = initialize(UDC_ID_TEST)
        authentication = bannerSamlAuthenticationProvider.authenticate(token)

        assertNotNull(authentication)

        //  deleteUdcID(bannerPidm)
        Holders?.config.ssbEnabled = false
    }

    /**
     * Verifies that authentication process does not fail if UDC_IDENTIFIER passed maps to disabled Oracle user.
     *
     * @throws Exception error
     */
    @Test
    public void testAuthenticateOracleDisabledUser() {
        SAMLAuthenticationToken token = initialize(UDC_ID_TEST_DISABLED)
        assertNotNull(bannerSamlAuthenticationProvider.authenticate(token))
    }

    /* @Test
     public void testMessageContextChange() {
         SAMLAuthenticationToken token = initialize(UDC_ID_TEST_DISABLED)
         SAMLMessageContext context = token.getCredentials();
         context.setCommunicationProfileId(SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI)
         assertNotNull(bannerSamlAuthenticationProvider.authenticate(token))
     }*/

    @Test
    public void testMessageContextEmpty(){
        SAMLAuthenticationToken token = initialize(UDC_ID_TEST_DISABLED)
        SAMLMessageContext context = token.getCredentials();
        context.setCommunicationProfileId("")
        try {
            bannerSamlAuthenticationProvider.authenticate(token)
        } catch (Exception e) {
            assertEquals("Error validating SAML message", e.message)
        }
    }

    /**
     * Please put all the custom tests in this protected section to protect the code
     * from being overwritten on re-generation
     */
    /*PROTECTED REGION ID(MenuAndToolbarPreference_custom_integration_test_methods) ENABLED START*/
    /*PROTECTED REGION END*/
    private def isSsbEnabled() {
        Holders.config.ssbEnabled instanceof Boolean ? Holders.config.ssbEnabled : false
    }

    private void replayMock() {

        replay(messageStorage);
        replay(nameID);
        replay(assertion);
    }

    public SAMLAuthenticationToken initialize(String UdcID) {
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

        Assertion assertion=buildAssertion(UdcID)
        response.getAssertions().add(assertion);
        messageContext = new SAMLMessageContext();
        messageContext.setInboundSAMLMessage(response)

        messageContext.peerEntityMetadata = ((SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME)).buildObject()
        messageContext.peerEntityMetadata.entityID = "http://localhost"

        SPSSODescriptor localEntityRoleMetadata = ((SAMLObjectBuilder<SPSSODescriptor>) builderFactory.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME)).buildObject()
        localEntityRoleMetadata.wantAssertionsSigned = false
        messageContext.localEntityRoleMetadata = localEntityRoleMetadata

        messageContext.setCommunicationProfileId(SAMLConstants.SAML2_WEBSSO_PROFILE_URI)

        Endpoint samlEndpoint = new SingleSignOnServiceImpl("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "UDC_IDENTIFIER", "name")
        samlEndpoint.setLocation("http://localhost")
        messageContext.localEntityEndpoint = samlEndpoint

        messageContext.localEntityId = "TestUri"  // should match Audience.uri

        ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(messageContext.getPeerEntityMetadata().getEntityID());
        messageContext.setPeerExtendedMetadata(extendedMetadata);


        messageContext.peerExtendedMetadata.supportUnsolicitedResponse=true;
        SAMLAuthenticationToken token = new SAMLAuthenticationToken(messageContext)

        replayMock();

        return token

    }
    public final Assertion buildAssertion(String UdcID) throws IllegalStateException {
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
        audience.setAudienceURI("TestUri");

        AudienceRestriction audienceRestrictions=((SAMLObjectBuilder<AudienceRestriction>) builderFactory
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME)).buildObject()
        audienceRestrictions.getAudiences().add(audience);

        conditions.getAudienceRestrictions().add(audienceRestrictions);

        Issuer issuer = ((SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
        issuer.setValue("http://localhost");

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

    /** Helper methods **/
    private ApplicationContext createUnderlyingSsbDataSourceBean() {
        def bb = new BeanBuilder()
        bb.beans {
            underlyingSsbDataSource(BasicDataSource) {
                maxActive = 5
                maxIdle = 2
                defaultAutoCommit = "false"
                driverClassName = "${Holders.config.bannerSsbDataSource.driver}"
                url = "${Holders.config.bannerSsbDataSource.url}"
                password = "${Holders.config.bannerSsbDataSource.password}"
                username = "${Holders.config.bannerSsbDataSource.username}"
            }
        }
        ApplicationContext testSpringContext = bb.createApplicationContext()
        return testSpringContext
    }

}