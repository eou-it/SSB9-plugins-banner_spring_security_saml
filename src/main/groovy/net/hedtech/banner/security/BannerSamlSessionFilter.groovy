/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
package net.hedtech.banner.security

import org.apache.log4j.Logger
import org.opensaml.common.SAMLException
import org.opensaml.common.SAMLRuntimeException
import org.opensaml.saml2.metadata.provider.MetadataProviderException
import org.opensaml.ws.message.decoder.MessageDecodingException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.saml.SAMLConstants
import org.springframework.security.saml.SAMLLogoutProcessingFilter
import org.springframework.security.saml.context.SAMLContextProvider
import org.springframework.security.saml.context.SAMLMessageContext
import org.springframework.security.saml.processor.SAMLProcessor
import org.springframework.web.filter.GenericFilterBean

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession

class BannerSamlSessionFilter extends GenericFilterBean{
    private static final Logger log = Logger.getLogger( BannerSamlSessionFilter.class )

    private BannerSamlSessionRegistryImpl sessionRegistry;
    private SAMLContextProvider contextProvider;
    private SAMLProcessor processor;
    @Override
    void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        HttpSession session = request.getSession(false);
        if(session==null){
            if(request.getRequestURL().contains(SAMLLogoutProcessingFilter.FILTER_URL)){
                log.debug  "BannerSamlSessionFilter.dofilter get request for single logout"
                SAMLMessageContext context;
                try {
                    context = contextProvider.getLocalEntity(request, response);
                    context.setCommunicationProfileId(SAMLConstants.SAML2_SLO_PROFILE_URI);
                    processor.retrieveMessage(context);
                    String sessionIndex=context.getInboundSAMLMessage().getProperties().get("sessionIndexes").getAt("sessionIndex").get(0);
                    String sessionId=sessionRegistry.getSessionIndexInformation(sessionIndex);
                    HttpSession httpsession= sessionRegistry.getSessionObjectInformation(sessionId);
                    if(httpsession!=null){
                        log.debug  "BannerSamlSessionFilter.dofilter found session from session regsitry $httpsession"
                        httpsession.invalidate();
                        sessionRegistry.removeSessionInformation(sessionId);
                    }
                } catch (SAMLException e) {
                    log.debug  "Incoming SAML message is invalid $e"
                    throw new SAMLRuntimeException("Incoming SAML message is invalid", e);
                } catch (MetadataProviderException e) {
                    log.debug  "Error determining metadata contracts $e"
                    throw new SAMLRuntimeException("Error determining metadata contracts", e);
                } catch (MessageDecodingException e) {
                    log.debug  "Error decoding incoming SAML message $e"
                    throw new SAMLRuntimeException("Error decoding incoming SAML message", e);
                } catch (org.opensaml.xml.security.SecurityException e) {
                    log.debug  "Incoming SAML message is invalid $e"
                    throw new SAMLRuntimeException("Incoming SAML message is invalid", e);
                }
            }
        }else{
            if(request.getRequestURL().contains(BannerSamlLogoutFilter.FILTER_URL)){
                log.debug  "BannerSamlSessionFilter.dofilter get request from application to logout"
                HttpSession httpSession=request.getSession(false);
                if(httpSession!=null){
                    sessionRegistry.removeSessionInformation(httpSession.getId());
                }
            }
        }
        chain.doFilter(request, response);
    }

    public void setSessionRegistry(BannerSamlSessionRegistryImpl sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }


    public void setContextProvider(SAMLContextProvider contextProvider) {
        this.contextProvider = contextProvider;
    }

    @Autowired
    public void setSAMLProcessor(SAMLProcessor processor) {
        this.processor = processor;
    }

}
