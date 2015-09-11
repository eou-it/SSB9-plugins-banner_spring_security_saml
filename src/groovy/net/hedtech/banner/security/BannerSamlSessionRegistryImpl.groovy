/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
package net.hedtech.banner.security

import org.apache.log4j.Logger

import javax.servlet.http.HttpSession

class BannerSamlSessionRegistryImpl {

    private static final Logger log = Logger.getLogger( BannerSamlSessionRegistryImpl.class )



    /** <sessionIndexIds:String,String> */
    private final Map<String, String> sessionIndexIds = Collections.synchronizedMap(new HashMap<String, String>());
/** <sessionObject:String,HttpSession> */
    private final Map<String, HttpSession> sessionObject = Collections.synchronizedMap(new HashMap<String, HttpSession>());

    //~ Methods ========================================================================================================

    public String getSessionIndexInformation(String sessionIndexId) {
        String key = null;
        for(Map.Entry<String, String> entry : sessionIndexIds.entrySet()) {
            if((sessionIndexId == null && entry.getValue() == null) || (sessionIndexId != null && sessionIndexId.equals(entry.getValue()))) {
                key = entry.getKey();
                break;
            }
        }
        return key;
    }
    public HttpSession getSessionObjectInformation(String sessionId) {

        return sessionObject.get(sessionId);
    }

    public synchronized void registerNewSession(HttpSession session,String sessionIndexId) {
        String sessionId=session.getId();
        if (log.isTraceEnabled()) {
            log.debug("Registering session " + sessionId);
        }
        if (log.isDebugEnabled()) {
            log.debug("Registering session " + sessionId);
        }

        sessionIndexIds.put(sessionId,sessionIndexId);
        sessionObject.put(sessionId,session);
    }

    public void removeSessionInformation(String sessionId) {

        if (log.isTraceEnabled()) {
            log.debug("Removing session " + sessionId + " from set of registered sessions");
        }

        if (log.isDebugEnabled()) {
            log.debug("Removing session " + sessionId + " from set of registered sessions");
        }

        sessionIndexIds.remove(sessionId);
        sessionObject.remove(sessionId);
    }

}
