/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.filter

import net.hedtech.banner.security.SessionCounterListener
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Ignore
import org.junit.Test
import org.junit.runners.MethodSorters
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpSession

import javax.servlet.http.HttpSession
import javax.servlet.http.HttpSessionEvent
import javax.servlet.http.HttpSessionListener

import static org.junit.Assert.assertNotEquals

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SessionCounterListenerTest {

    def HttpSessionListener counterListener;
    def HttpSession session;
    def HttpSession session1;
    def MockHttpServletRequest httpServletRequest;
    def MockHttpServletRequest httpServletRequest1;
    int totalActiveSession;
    HttpSessionEvent event;

    @Before
    public void setup(){
        counterListener= new SessionCounterListener();
        httpServletRequest= new MockHttpServletRequest();
        httpServletRequest1= new MockHttpServletRequest();
    }

    @Test
    public void dummytest(){
        
    }

    @Ignore
    public void "testSessionCreated"(){
        session=httpServletRequest.getSession();
        totalActiveSession=counterListener.getTotalActiveSession();
        session1=httpServletRequest1.getSession();
        int newSessionCount=counterListener.getTotalActiveSession();
        assertNotEquals(newSessionCount, totalActiveSession);


    }

    @Ignore
    public void "testSessionDestroyed"(){
        int activeSession= counterListener.getTotalActiveSession();
        session= httpServletRequest.getSession(false);
        session.invalidate();
        assertTrue("Session Destroyed", counterListener.getTotalActiveSession() < activeSession);
    }
}
