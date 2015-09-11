/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import net.hedtech.banner.security.SessionCounterListener
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters
import org.springframework.mock.web.MockHttpSession
import org.springframework.mock.web.MockServletContext
import org.springframework.web.context.support.StaticWebApplicationContext

import javax.servlet.http.HttpSessionEvent

import static org.junit.Assert.assertNotNull
import static org.junit.Assert.assertTrue

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SessionCounterListenerTest {

    @Test
    public void publishedEventIsReceivedbyListener() {
        SessionCounterListener counterListener = new SessionCounterListener();

        StaticWebApplicationContext context = new StaticWebApplicationContext();

        MockServletContext servletContext = new MockServletContext();
        servletContext.setAttribute(StaticWebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, context);

        context.setServletContext(servletContext);
        context.registerSingleton("listener", SessionCounterListener.class, null);
        context.refresh();

        MockHttpSession session = new MockHttpSession(servletContext);
        SessionCounterListener listener = (SessionCounterListener) context.getBean("listener");

        HttpSessionEvent event = new HttpSessionEvent(session);

        counterListener.sessionCreated(event);

        assertNotNull(listener.getTotalActiveSession());
    }

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

    @Test(expected=NullPointerException.class)
    public void sessionDestroyed() {
        SessionCounterListener counterListener = new SessionCounterListener();
        MockServletContext servletContext = new MockServletContext();
        MockHttpSession session = new MockHttpSession(servletContext);
        HttpSessionEvent event = new HttpSessionEvent(session);

        counterListener.sessionDestroyed(event);
    }


}
