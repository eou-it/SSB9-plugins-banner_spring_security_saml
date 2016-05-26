/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import grails.spring.BeanBuilder
import grails.util.Holders
import groovy.sql.Sql
import net.hedtech.banner.testing.BaseIntegrationTestCase
import org.apache.commons.dbcp.BasicDataSource
import org.codehaus.groovy.runtime.typehandling.GroovyCastException
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.opensaml.Configuration
import org.opensaml.saml2.core.Assertion
import org.opensaml.saml2.core.NameID
import org.opensaml.xml.XMLObjectBuilderFactory
import org.springframework.context.ApplicationContext
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

    public static final String UDC_IDENTIFIER = '99999SAML99999'

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

    def udc_id
    def bannerPidm

    @Before
    public void setUp() {
        Holders?.config.ssbEnabled = true

        ApplicationContext testSpringContext = createUnderlyingSsbDataSourceBean()
        dataSource.underlyingSsbDataSource =  testSpringContext.getBean("underlyingSsbDataSource")

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

        bannerPidm = generatePidm()
        udc_id = createUdcID(bannerPidm)



    }

    @After
    public void tearDown() {
        deleteUdcID(bannerPidm)
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

        SAMLAuthenticationToken token = bannerSamlUtility.initialize(udc_id, false, builderFactory, metadata);
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
        SAMLAuthenticationToken token = bannerSamlUtility.initialize(udc_id, false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        request.setParameter("local", "false");
        assertTrue(filter.isGlobalLogout(request, authentication))

    }

    @Test
    public void "validation isLocalLogout "() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize(udc_id, false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        request.setParameter("local", "true");
        assertFalse(filter.isGlobalLogout(request, authentication))

    }

    @Test
    public void "validation isGlobalLogout with no local parameter "() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize(udc_id, false, builderFactory, metadata);
        authentication = (BannerAuthenticationToken) bannerSamlAuthenticationProvider.authenticate(token)
        assertTrue(filter.isGlobalLogout(request, authentication))

    }

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();


    @Test
    public void " Validate Global logout pass if local = false in request"() {
        BannerAuthenticationToken authentication
        SAMLAuthenticationToken token = bannerSamlUtility.initialize(udc_id, false, builderFactory, metadata);
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
        SAMLAuthenticationToken token = bannerSamlUtility.initialize(udc_id, false, builderFactory, metadata);
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
        SAMLAuthenticationToken token = bannerSamlUtility.initialize(udc_id, false, builderFactory, metadata);
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
        SAMLAuthenticationToken token = bannerSamlUtility.initialize(udc_id, false, builderFactory, metadata);
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
        SAMLAuthenticationToken token = bannerSamlUtility.initialize(udc_id, true, builderFactory, metadata);
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

    private def createUdcID(bannerPidm) {

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
}
