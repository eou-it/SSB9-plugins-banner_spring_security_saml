/*******************************************************************************
 Copyright 2009-2020 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
package net.hedtech.banner.security

import grails.util.Holders
import groovy.util.logging.Slf4j
import net.hedtech.banner.general.audit.LoginAuditService
import org.opensaml.saml2.core.impl.AuthnStatementImpl
import org.opensaml.common.SAMLException
import org.opensaml.common.SAMLRuntimeException
import org.opensaml.xml.encryption.DecryptionException
import org.opensaml.xml.schema.XSAny
import org.opensaml.xml.validation.ValidationException
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml.SAMLAuthenticationProvider
import org.springframework.security.saml.SAMLAuthenticationToken
import org.springframework.security.saml.SAMLConstants
import org.springframework.security.saml.SAMLCredential
import org.springframework.security.saml.context.SAMLMessageContext
import org.springframework.web.context.request.RequestContextHolder as RCH

/**
 * An authentication provider for Banner that authenticates a user using SAML.
 */
@Slf4j
class BannerSamlAuthenticationProvider extends SAMLAuthenticationProvider  {
    def dataSource
    def loginAuditService

    public BannerSamlAuthenticationProvider() {
        super();
    }

    /**
     * Attempts to perform authentication of an Authentication object. The authentication must be of type
     * SAMLAuthenticationToken and must contain filled SAMLMessageContext. If the SAML inbound message
     * in the context is valid, UsernamePasswordAuthenticationToken with name given in the SAML message NameID
     * and assertion used to verify the user as credential (SAMLCredential object) is created and set as authenticated.
     *
     * @param authentication SAMLAuthenticationToken to verify
     * @return BannerAuthenticationToken with name as NameID value and SAMLCredential as credential object
     * @throws AuthenticationException user can't be authenticated due to an error
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Only SAMLAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        SAMLAuthenticationToken token = (SAMLAuthenticationToken) authentication;
        SAMLMessageContext context = token.getCredentials();
        SAMLCredential credential;

        try {
            if (SAMLConstants.SAML2_WEBSSO_PROFILE_URI.equals(context.getCommunicationProfileId())) {
                credential = consumer.processAuthenticationResponse(context);
            } else if (SAMLConstants.SAML2_HOK_WEBSSO_PROFILE_URI.equals(context.getCommunicationProfileId())) {
                credential = hokConsumer.processAuthenticationResponse(context);
            } else {
                throw new SAMLException("Unsupported profile encountered in the context " + context.getCommunicationProfileId());
            }
        } catch (SAMLRuntimeException e) {
            log.error  "BannerSamlAuthenticationProvider.authenticate ecountered an SAMLRuntimeException $e"
            throw new AuthenticationServiceException("Error validating SAML message", e)
        } catch (SAMLException e) {
            log.error "BannerSamlAuthenticationProvider.authenticate ecountered an SAMLException $e"
            throw new AuthenticationServiceException("Error validating SAML message", e)
        } catch (ValidationException e) {
            log.error  "BannerSamlAuthenticationProvider.authenticate ecountered an ValidationException $e"
            throw new AuthenticationServiceException("Error validating SAML message signature", e)
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.error  "BannerSamlAuthenticationProvider.authenticate ecountered an SecurityException $e"
            throw new AuthenticationServiceException("Error validating SAML message signature", e)
        } catch (DecryptionException e) {
            log.error "BannerSamlAuthenticationProvider.authenticate ecountered an DecryptionException $e"
            throw new AuthenticationServiceException("Error decrypting SAML message", e)
        }

        Map claims = new HashMap()
        String assertAttributeValue
        RCH.currentRequestAttributes().request.session.setAttribute("auth_name", credential.nameID.getValue())
        def authenticationAssertionAttribute = Holders?.config?.banner.sso.authenticationAssertionAttribute
        log.debug  "BannerSamlAuthenticationProvider.authenticate found assertAttribute $authenticationAssertionAttribute"

        for(attribute in credential.getAttributes()) {
            if(attribute.name == authenticationAssertionAttribute) {
                //assertAttributeValue = attribute.attributeValues.get(0).getValue()
                assertAttributeValue = getAttributeValue(attribute.attributeValues.get(0))
                log.debug "BannerSamlAuthenticationProvider.authenticate found assertAttributeValue $assertAttributeValue"
            } else {
                //def value = attribute.attributeValues.get(0).getValue()
                def value = getAttributeValue(attribute.attributeValues.get(0))
                claims.put(attribute.name, value)
                log.debug  "BannerSamlAuthenticationProvider.authenticate found claim value $value"
            }
        }

        if(assertAttributeValue == null ) {
            log.error("System is configured for SAML authentication and identity assertion is $authenticationAssertionAttribute is null")  // NULL
            throw new UsernameNotFoundException("System is configured for SAML authentication and identity assertion $authenticationAssertionAttribute is null")
        }

        def dbUser = AuthenticationProviderUtility.getMappedUserForUdcId( assertAttributeValue, dataSource )
        if (dbUser?.locked){
            String user =  RCH.currentRequestAttributes().request.session.getAttribute('auth_name')
            log.debug "BannerSamlAuthenticationProvider was not able to authenticate user=$user is Locked."
        }

        def dbUserLog =dbUser.findAll {it.key != "pidm"}

        log.debug "BannerSamlAuthenticationProvider.authenticate found Oracle database user $dbUserLog for assertAttributeValue"

        String loginAuditConfiguration = AuthenticationProviderUtility.getLoginAuditConfiguration()
        if(dbUser!= null && loginAuditConfiguration?.equalsIgnoreCase('Y')){
            if (!loginAuditService) {
                loginAuditService = Holders.grailsApplication.mainContext.getBean("loginAuditService")
            }
            String loginComment = "Login successful"
            loginAuditService.createLoginLogoutAudit(dbUser?.name, dbUser?.pidm, loginComment)
        }

        // Next, we'll verify the authenticationResults (and throw appropriate exceptions for expired pin, disabled account, etc.)
        AuthenticationProviderUtility.verifyAuthenticationResults this, authentication, dbUser
        log.debug "BannerSamlAuthenticationProvider.authenticate verify authentication results"

        BannerAuthenticationToken bannerAuthenticationToken = AuthenticationProviderUtility.createAuthenticationToken(dbUser,dataSource, this)
        bannerAuthenticationToken.claims = claims
        bannerAuthenticationToken.SAMLCredential = credential
        bannerAuthenticationToken.sessionIndex = credential.getAuthenticationAssertion().getStatements().find({it instanceof AuthnStatementImpl})?.getAt("sessionIndex")
        log.debug "BannerSamlAuthenticationProvider.authenticate BannerAuthenticationToken updated with claims $bannerAuthenticationToken"

        return bannerAuthenticationToken

    }


    private def getAttributeValue(def element) {
        def value
        if (element instanceof XSAny) {
            value = element.getTextContent()
        } else {
            value = element.getValue()
        }
        return value
    }
}
