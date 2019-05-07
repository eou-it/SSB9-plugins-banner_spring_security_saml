/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
package net.hedtech.banner.security

import net.hedtech.banner.security.BannerAuthenticationToken
import groovy.util.logging.Slf4j
import org.opensaml.common.SAMLException
import org.opensaml.saml2.metadata.provider.MetadataProviderException
import org.opensaml.ws.message.encoder.MessageEncodingException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.context.SAMLContextProvider
import org.springframework.security.saml.context.SAMLMessageContext
import org.springframework.security.saml.util.SAMLUtil
import org.springframework.security.saml.websso.SingleLogoutProfile
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler
import org.springframework.util.Assert

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


/**
 * An Filter added to handle the SAMl logout with token of type BannerAuthenticationToken.
 */
@Slf4j
class BannerSamlLogoutFilter extends LogoutFilter {

    protected SAMLContextProvider contextProvider
    protected SingleLogoutProfile profile
    /**
     * Name of parameter of HttpRequest indicating whether this call should perform only local logout.
     * In case the value is true no global logout will be invoked.
     */
    protected static final String LOGOUT_PARAMETER = "local"
    /**
     * Handlers to be invoked during logout.
     */
    protected LogoutHandler[] globalHandlers

    /**
     * URL this filter processes
     */
    public static final String FILTER_URL = "/saml/logout";

    BannerSamlLogoutFilter(String successUrl, LogoutHandler[] localHandler, LogoutHandler[] globalHandlers) {
        super(successUrl, localHandler)
        this.globalHandlers = globalHandlers
        this.setFilterProcessesUrl(FILTER_URL)
    }

    BannerSamlLogoutFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler[] localHandler, LogoutHandler[] globalHandlers) {
        super(logoutSuccessHandler, localHandler)
        this.globalHandlers = globalHandlers
        this.setFilterProcessesUrl(FILTER_URL)
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain)
        processLogout(fi.getRequest(), fi.getResponse(), chain)
    }

    public void processLogout(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        if (requiresLogout(request, response)) {

            try {
                BannerAuthenticationToken auth=SecurityContextHolder.getContext().getAuthentication();
                if (auth != null && isGlobalLogout(request,auth)  && auth.getSAMLCredential() != null) {
                    if(!(auth instanceof BannerAuthenticationToken)) {
                        log.error("Authentication object doesn't contain SAML credential, cannot perform global logout")
                        throw new ServletException("Authentication object doesn't contain SAML credential, cannot perform global logout")
                    }
                    for (LogoutHandler handler : globalHandlers) {
                        handler.logout(request,response,auth)
                    }
                    SAMLCredential samlCredential = (SAMLCredential)auth.getSAMLCredential();
                    request.setAttribute("localEntityId", samlCredential.getLocalEntityID());
                    request.setAttribute("peerEntityId", samlCredential.getRemoteEntityID());
                    SAMLMessageContext context = this.contextProvider.getLocalAndPeerEntity(request, response);
                    profile.sendLogoutRequest(context,samlCredential)
                    log.debug("Logout Request initiated with ontext : " + context)
                }
                else {
                    log.error("Error initializing global logout due to internal errors. Only Local logout will be initiated.")
                    super.doFilter(request,response,chain)
                }
            } catch (SAMLException e1) {
                log.error("Error initializing global logout " + e1)
                throw new ServletException("Error initializing global logout", e1)
            } catch (MetadataProviderException e1) {
                log.error("Error processing metadata " + e1)
                throw new ServletException("Error processing metadata", e1)
            } catch (MessageEncodingException e1) {
                log.error("Error encoding outgoing message " + e1)
                throw new ServletException("Error encoding outgoing message", e1)
            }
        } else {
            chain.doFilter(request, response)
        }

    }

    /**
     * The filter will be used in case the URL of the request contains the DEFAULT_FILTER_URL.
     *
     * @param request request used to determine whether to enable this filter
     * @return true if this filter should be used
     */
   /* @Override
    protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
        return requiresLogout
    }*/

    /**
     * Performs global logout in case current user logged in using SAML and user hasn't selected local logout only
     *
     * @param request request
     * @param auth    currently logged in user
     * @return true if single logout with IDP is required
     */
    protected boolean isGlobalLogout(HttpServletRequest request, Authentication auth) {
        String login = request.getParameter(LOGOUT_PARAMETER)
        return (login == null || !"true".equals(login.toLowerCase().trim())) && (auth instanceof BannerAuthenticationToken)
    }

    /**
     * Profile for consumption of processed messages, cannot be null, must be set.
     *
     * @param profile profile
     */
    @Autowired
    public void setProfile(SingleLogoutProfile profile) {
        Assert.notNull(profile, "SingleLogoutProfile can't be null")
        this.profile = profile
    }

    /**
     * Sets entity responsible for populating local entity context data. Cannot be null, must be set.
     *
     * @param contextProvider provider implementation
     */
    @Autowired
    public void setContextProvider(SAMLContextProvider contextProvider) {
        Assert.notNull(contextProvider, "Context provider can't be null")
        this.contextProvider = contextProvider
    }


}
