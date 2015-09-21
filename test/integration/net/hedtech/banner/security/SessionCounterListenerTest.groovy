/*******************************************************************************
 Copyright 2015 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import net.hedtech.banner.security.SessionCounterListener
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters
import org.springframework.mock.web.MockHttpSession
import org.springframework.mock.web.MockServletContext
import org.springframework.web.context.WebApplicationContext

import javax.servlet.http.HttpSessionEvent

import static org.junit.Assert.assertTrue

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SessionCounterListenerTest {

    def grailsApplication

    @Test
    public void sessionCreated() {
        SessionCounterListener counterListener = new SessionCounterListener();
        MockServletContext servletContext = new MockServletContext();
        MockHttpSession session = new MockHttpSession(servletContext);
        HttpSessionEvent event = new HttpSessionEvent(session);
        int initialCount= counterListener.getTotalActiveSession();
        counterListener.sessionCreated(event);
        assertTrue("SessionCount",counterListener.getTotalActiveSession()>initialCount);
    }

    @Test
    public void sessionDestroyed() {
        SessionCounterListener counterListener = new SessionCounterListener();
        MockServletContext servletContext = new MockServletContext();
        servletContext.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, grailsApplication?.mainContext);
        MockHttpSession session = new MockHttpSession(servletContext);
        HttpSessionEvent event = new HttpSessionEvent(session);

        int initialCount= counterListener.getTotalActiveSession();
        counterListener.sessionCreated(event);
        assertTrue("SessionCount",counterListener.getTotalActiveSession()>initialCount);

        counterListener.sessionDestroyed(event);
        assertTrue("SessionCount",counterListener.getTotalActiveSession()==initialCount);
    }


}
