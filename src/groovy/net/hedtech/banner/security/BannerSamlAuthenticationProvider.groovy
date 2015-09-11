/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
package net.hedtech.banner.security

import grails.util.Holders
import org.apache.log4j.Logger
import org.opensaml.common.SAMLException
import org.opensaml.common.SAMLRuntimeException
import org.opensaml.xml.encryption.DecryptionException
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

/**
 * An authentication provider for Banner that authenticates a user using SAML.
 */
class BannerSamlAuthenticationProvider extends SAMLAuthenticationProvider  {
    def dataSource
    // note: using 'getClass()' here doesn't work
    private static final Logger log = Logger.getLogger( "net.hedtech.banner.security.BannerSamlAuthenticationProvider" )

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
            log.fatal  "BannerSamlAuthenticationProvider.authenticate ecountered an SAMLRuntimeException $e"
            throw new AuthenticationServiceException("Error validating SAML message", e)
        } catch (SAMLException e) {
            log.fatal  "BannerSamlAuthenticationProvider.authenticate ecountered an SAMLException $e"
            throw new AuthenticationServiceException("Error validating SAML message", e)
        } catch (ValidationException e) {
            log.fatal  "BannerSamlAuthenticationProvider.authenticate ecountered an ValidationException $e"
            throw new AuthenticationServiceException("Error validating SAML message signature", e)
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.fatal  "BannerSamlAuthenticationProvider.authenticate ecountered an SecurityException $e"
            throw new AuthenticationServiceException("Error validating SAML message signature", e)
        } catch (DecryptionException e) {
            log.fatal "BannerSamlAuthenticationProvider.authenticate ecountered an DecryptionException $e"
            throw new AuthenticationServiceException("Error decrypting SAML message", e)
        }

        Map claims = new HashMap();
        String assertAttributeValue
        def authenticationAssertionAttribute = Holders?.config?.banner.sso.authenticationAssertionAttribute
        log.debug  "BannerSamlAuthenticationProvider.authenticate found assertAttribute $authenticationAssertionAttribute"

        for(attribute in credential.getAttributes()) {
            if(attribute.name == authenticationAssertionAttribute) {
                assertAttributeValue = attribute.attributeValues.get(0).getValue()
                log.debug  "BannerSamlAuthenticationProvider.authenticate found assertAttributeValue $assertAttributeValue"
            } else {
                def value = attribute.attributeValues.get(0).getValue()
                claims.put(attribute.name, value)
                log.debug  "BannerSamlAuthenticationProvider.authenticate found claim value $value"
            }
        }

        if(assertAttributeValue == null ) {
            log.fatal("System is configured for SAML authentication and identity assertion is $authenticationAssertionAttribute is null")  // NULL
            throw new UsernameNotFoundException("System is configured for SAML authentication and identity assertion $authenticationAssertionAttribute is null")
        }

        def dbUser = AuthenticationProviderUtility.getMappedUserForUdcId( assertAttributeValue, dataSource )
        log.debug "BannerSamlAuthenticationProvider.authenticate found Oracle database user $dbUser for assertAttributeValue"

        // Next, we'll verify the authenticationResults (and throw appropriate exceptions for expired pin, disabled account, etc.)
        AuthenticationProviderUtility.verifyAuthenticationResults this, authentication, dbUser
        log.debug "BannerSamlAuthenticationProvider.authenticate verify authentication results"

        BannerAuthenticationToken bannerAuthenticationToken = AuthenticationProviderUtility.createAuthenticationToken(dbUser,dataSource, this)
        bannerAuthenticationToken.claims = claims
        bannerAuthenticationToken.SAMLCredential=credential
        bannerAuthenticationToken.sessionIndex=credential.getAuthenticationAssertion().getStatements().get(0).getAt("sessionIndex")

        log.debug "BannerSamlAuthenticationProvider.authenticate BannerAuthenticationToken updated with claims $bannerAuthenticationToken"

        return bannerAuthenticationToken

    }


}
