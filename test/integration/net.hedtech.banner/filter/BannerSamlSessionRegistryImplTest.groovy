/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.filter

import net.hedtech.banner.security.BannerSamlSessionRegistryImpl
import net.hedtech.banner.security.SessionCounterListener
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException
import org.opensaml.common.SAMLRuntimeException
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import javax.servlet.http.HttpSession;
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNotEquals
import static org.junit.Assert.assertNull

class BannerSamlSessionRegistryImplTest {


    def BannerSamlSessionRegistryImpl sessionRegistry;
    def SessionCounterListener counterListener;
    def HttpSession session;
    def String randomId;
    def MockHttpServletRequest request;

    @Before
    public void setup() {
        randomId=generateId();
        request= new MockHttpServletRequest();
        session= request.getSession(true);
        sessionRegistry=new BannerSamlSessionRegistryImpl();
        counterListener= new SessionCounterListener();
    }

    protected String generateId(){
        String id = "_" + Integer.toHexString(new Random().nextInt(Integer.MAX_VALUE)) + "-" + Integer.toHexString(new Random().nextInt(Integer.MAX_VALUE));
        return id;
    }

    @Test
    public void "testRegisterNewSession"() {
        sessionRegistry.registerNewSession(session,randomId);
        assertEquals(sessionRegistry.getSessionObjectInformation(session.getId()),session);
    }



    @Test
    public void "testRemoveSessionInformation"() {
        sessionRegistry.removeSessionInformation(session.getId().toString());
        assertNull(sessionRegistry.getSessionObjectInformation(session.getId()));
    }

    @Test
    public void "testgetSessionIndexInformation"(){
        sessionRegistry.registerNewSession(session,randomId);
        assertEquals(sessionRegistry.getSessionIndexInformation(randomId),session.getId());
    }




}
