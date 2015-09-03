/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
package net.hedtech.banner.security

import org.apache.log4j.Logger
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class BannerSamlSavedRequestAwareAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private static final Logger log = Logger.getLogger( BannerSamlSavedRequestAwareAuthenticationSuccessHandler.class )
    BannerSamlSessionRegistryImpl sessionRegistry;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {

        BannerAuthenticationToken token = (BannerAuthenticationToken) authentication;
        String sessionIndex= token.getsessionIndex();
        log.debug  "BannerSamlSavedRequestAwareAuthenticationSuccessHandler.onAuthenticationSuccess adding new session in sessionregistry $sessionIndex"
        sessionRegistry.registerNewSession(request.getSession(),sessionIndex);
        super.onAuthenticationSuccess(request, response, authentication);
    }


}
