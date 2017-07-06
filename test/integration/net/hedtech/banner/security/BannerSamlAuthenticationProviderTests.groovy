/*******************************************************************************
 Copyright 2015-2017 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import grails.spring.BeanBuilder
import grails.util.Holders
import groovy.sql.Sql
import net.hedtech.banner.security.BannerAuthenticationToken
import net.hedtech.banner.testing.BaseIntegrationTestCase
import org.apache.commons.dbcp.BasicDataSource
import org.joda.time.DateTime
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.opensaml.Configuration
import org.opensaml.common.SAMLException
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
import org.springframework.security.authentication.AuthenticationServiceException
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

    public static final String UDC_IDENTIFIER = '99999SAML99999'
    public static final String USER_NAME = 'BCMADMIN'
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

    /* private def createUdcID(bannerPidm) {

         def bannerId = "DUMMYSAML"

         generateSpridenRecord(bannerId, bannerPidm)
         addStudentRoleToSpriden(bannerPidm)

         def bannerUDCID = generateUDCIDMappingPIDM(bannerPidm)

         return bannerUDCID
     }


      private void deleteUdcID(bannerPidm) {
          deleteSpriden(bannerPidm)
          deleteUDCIDMappingPIDM()
      }

      private getDB() {
          def configFile = new File("${System.properties['user.home']}/.grails/banner_configuration.groovy")
          def slurper = new ConfigSlurper(grails.util.GrailsUtil.environment)
          def config = slurper.parse(configFile.toURI().toURL())
          def url = config.get("bannerDataSource").url
          def db = Sql.newInstance(url,   //  db =  new Sql( connectInfo.url,
                  "baninst1",
                  "u_pick_it",
                  'oracle.jdbc.driver.OracleDriver')
          db
      }

      private def generatePidm() {

          def sql = getDB();

          String idSql = """select gb_common.f_generate_pidm pidm from dual """
          def bannerValues = sql.firstRow(idSql)

          sql?.close() // note that the test will close the connection, since it's our current session's connection

          return bannerValues.pidm
      }


      private void generateSpridenRecord(bannerId, bannerPidm) {

          def sql = getDB();

          sql.call("""
           declare

           Lv_Id_Ref Gb_Identification.Identification_Ref;

           spriden_current Gb_Identification.identification_rec;
           test_pidm spriden.spriden_pidm%type;
           test_rowid varchar2(30);
           begin

           gb_identification.p_create(
           P_ID_INOUT => ${bannerId},
           P_LAST_NAME => 'Miller',
           P_FIRST_NAME => 'Ann',
           P_MI => 'Elizabeth',
           P_CHANGE_IND => NULL,
           P_ENTITY_IND => 'P',
           P_User => User,
           P_ORIGIN => 'banner',
           P_NTYP_CODE => NULL,
           P_DATA_ORIGIN => 'banner',
           P_PIDM_INOUT => ${bannerPidm},
           P_Rowid_Out => Test_Rowid);
           end ;
           """)

          sql.commit()
          sql.close()
      }

      private void addStudentRoleToSpriden(pidm) {

          def db = getDB();

          db.executeUpdate("Insert Into Twgrrole ( Twgrrole_Pidm, Twgrrole_Role, Twgrrole_Activity_Date) values ( ${pidm}, 'STUDENT', Sysdate)")
          db.commit()
          db.executeUpdate("INSERT INTO SGBSTDN (SGBSTDN_PIDM,SGBSTDN_TERM_CODE_EFF,SGBSTDN_STST_CODE,SGBSTDN_LEVL_CODE,SGBSTDN_STYP_CODE,SGBSTDN_TERM_CODE_ADMIT,SGBSTDN_CAMP_CODE,SGBSTDN_RESD_CODE,SGBSTDN_COLL_CODE_1,SGBSTDN_DEGC_CODE_1,SGBSTDN_MAJR_CODE_1,SGBSTDN_ACTIVITY_DATE,SGBSTDN_BLCK_CODE,SGBSTDN_PRIM_ROLL_IND,SGBSTDN_PROGRAM_1,SGBSTDN_DATA_ORIGIN,SGBSTDN_USER_ID,SGBSTDN_SURROGATE_ID,SGBSTDN_VERSION) values (${pidm},'201410','AS','UG','S','201410','M','R','AS','BA','HIST',to_date('02-MAR-14','DD-MON-RR'),'NUTR','N','BA-HIST','Banner','BANPROXY',SGBSTDN_SURROGATE_ID_SEQUENCE.nextval,1)")
          db.commit()
          db.close()

      }

      private def generateUDCIDMappingPIDM(pidm) {

          def db = getDB();

          db.call("""
           declare
           test_rowid varchar2(30);
           begin

           gb_gobumap.p_create(
           p_udc_id => ${UDC_IDENTIFIER},
           p_pidm => ${pidm},
           p_create_date => sysdate,
           p_user_id => 'banner',
           p_data_origin => 'banner',
           P_Rowid_Out => Test_Rowid);

           end ;
           """)


          String idSql = """select GOBUMAP_UDC_ID from gobumap where gobumap_udc_id = '${UDC_IDENTIFIER}' """
          def bannerValues = db.firstRow(idSql)
          def spridenId
          def sqlStatement2 = '''SELECT spriden_id, gobumap_pidm FROM gobumap,spriden WHERE spriden_pidm = gobumap_pidm AND spriden_change_ind is null AND gobumap_udc_id = ?'''
          db.eachRow(sqlStatement2, [UDC_IDENTIFIER]) { row ->
              spridenId = row.spriden_id
              pidm = row.gobumap_pidm
          }

          db.commit()
          db.close()

          return bannerValues.GOBUMAP_UDC_ID
      }

      private void deleteSpriden(pidm) {

          def db = getDB();

          db.executeUpdate("delete spriden where spriden_pidm=${pidm}")
          db.commit()
          db.close()
      }

      private void deleteUDCIDMappingPIDM() {

          def db = getDB();

          db.call("""
           declare
           test_rowid varchar2(30);
           begin

           gb_gobumap.p_delete(
           p_udc_id => ${UDC_IDENTIFIER});

           end ;
           """)

          db.commit()
          db.close()
      }

      private def getOracleUser() {
          def db = getDB()
          def user = [udcID: '', pidm: '']

          def sqlStatement2 = '''SELECT GOBUMAP_UDC_ID, GOBUMAP_PIDM FROM GOBUMAP WHERE GOBUMAP_PIDM IN (SELECT GOBEACC_PIDM FROM GOBEACC where gobeacc_username = ?)'''
          db.eachRow(sqlStatement2, [USER_NAME]) { row ->
              user.udcID = row.GOBUMAP_UDC_ID
              user.pidm = row.GOBUMAP_PIDM
          }

          db.close()

          return user
      }

     /* private void disableOracleUser(pidm) {
          def db = getDB()

          db.executeUpdate("UPDATE GOBTPAC SET GOBTPAC_PIN_DISABLED_IND = 'Y' WHERE GOBTPAC_PIDM = ${pidm}")
          db.commit()

          db.close()

      }

      private void enableOracleUser(pidm) {

          def db = getDB()

          db.executeUpdate("UPDATE GOBTPAC SET GOBTPAC_PIN_DISABLED_IND = 'N' WHERE GOBTPAC_PIDM = ${pidm}")
          db.commit()

          db.close()

      }

      private getPidm(String bannerId) {
          def pidm
          dataSource.eachRow("select spriden_pidm from spriden where spriden_id = ? and spriden_change_ind is null", [bannerId]) {
              pidm = it.spriden_pidm
          }
          return pidm
      }*/
}