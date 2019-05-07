/* ******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 ****************************************************************************** */


package net.hedtech.banner.security

import groovy.util.logging.Slf4j
import org.springframework.context.ApplicationContext
import org.springframework.web.context.support.WebApplicationContextUtils

import javax.servlet.http.HttpSessionEvent
import javax.servlet.http.HttpSessionListener

@Slf4j
public class SessionCounterListener implements HttpSessionListener {

    private static int totalActiveSessions;

    public static int getTotalActiveSession(){
        return totalActiveSessions;
    }

    @Override
    public void sessionCreated(HttpSessionEvent sessionEvent) {
        totalActiveSessions++;
        log.debug("sessionCreated - add one session into counter : "+sessionEvent.getSession());
        log.debug("Total active session : "+totalActiveSessions);

    }

    @Override
    public void sessionDestroyed(HttpSessionEvent sessionEvent) {
        totalActiveSessions--;
        log.debug("sessionDestroyed - deduct one session from counter : "+sessionEvent.getSession());
        log.debug("Total active session : "+totalActiveSessions);
        ApplicationContext ctx =
                WebApplicationContextUtils.
                        getWebApplicationContext(sessionEvent.getSession().getServletContext());
        BannerSamlSessionRegistryImpl sessionRegistry =
                (BannerSamlSessionRegistryImpl) ctx.getBean("samlSessionRegistry");
        sessionRegistry.removeSessionInformation(sessionEvent.getSession().getId());
    }
}
