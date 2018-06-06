/*******************************************************************************
 Copyright 2009-2014 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/

package net.hedtech.banner.security

import org.joda.time.DateTime
import org.opensaml.Configuration
import org.opensaml.common.SAMLObjectBuilder
import org.opensaml.common.SAMLVersion
import org.opensaml.saml2.core.*
import org.opensaml.saml2.metadata.Endpoint
import org.opensaml.saml2.metadata.EntityDescriptor
import org.opensaml.saml2.metadata.SPSSODescriptor
import org.opensaml.saml2.metadata.impl.SingleSignOnServiceImpl
import org.opensaml.xml.XMLObjectBuilderFactory
import org.opensaml.xml.schema.XSString
import org.opensaml.xml.schema.impl.XSStringBuilder
import org.springframework.security.saml.SAMLAuthenticationToken
import org.springframework.security.saml.SAMLConstants
import org.springframework.security.saml.context.SAMLMessageContext
import org.springframework.security.saml.metadata.ExtendedMetadata
import org.springframework.security.saml.metadata.MetadataManager
import org.springframework.security.saml.storage.SAMLMessageStorage

import static org.easymock.EasyMock.replay

public class BannerSamlUtility {


    NameID nameID
    Assertion assertionobj
    SAMLMessageStorage messageStorage
    SAMLMessageContext messageContext

    void setNameID(NameID nameID) {
        this.nameID = nameID
    }

    void setAssertion(Assertion assertionobj) {
        this.assertionobj = assertionobj
    }

    void setMessageStorage(SAMLMessageStorage messageStorage) {
        this.messageStorage = messageStorage
    }

    public SAMLAuthenticationToken initialize(String UdcID, boolean issuerFlag, XMLObjectBuilderFactory builderFactory, MetadataManager metadata) {
        SAMLObjectBuilder<Response> builder = (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = builder.buildObject();
        response.setIssueInstant(new DateTime());
        response.setInResponseTo(generateId());

        StatusCode statusCode = ((SAMLObjectBuilder<StatusCode>) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME)).buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);
        Status status = ((SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME)).buildObject();
        status.setStatusCode(statusCode);
        response.setStatus(status);

        Assertion assertion = buildAssertion(UdcID, issuerFlag, builderFactory)
        response.getAssertions().add(assertion);

        messageContext = new SAMLMessageContext();
        messageContext.setInboundSAMLMessage(response)

        messageContext.peerEntityMetadata = ((SAMLObjectBuilder<EntityDescriptor>) builderFactory.getBuilder(EntityDescriptor.DEFAULT_ELEMENT_NAME)).buildObject()
        messageContext.peerEntityMetadata.entityID = "localhost:default:entityId"

        SPSSODescriptor localEntityRoleMetadata = ((SAMLObjectBuilder<SPSSODescriptor>) builderFactory.getBuilder(SPSSODescriptor.DEFAULT_ELEMENT_NAME)).buildObject()
        localEntityRoleMetadata.wantAssertionsSigned = false
        messageContext.localEntityRoleMetadata = localEntityRoleMetadata

        messageContext.setCommunicationProfileId(SAMLConstants.SAML2_WEBSSO_PROFILE_URI)

        Endpoint samlEndpoint = new SingleSignOnServiceImpl("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "UDC_IDENTIFIER", "name")
        samlEndpoint.setLocation("http://localhost")
        messageContext.localEntityEndpoint = samlEndpoint

        messageContext.localEntityId = "test"  // should match Audience.uri

        ExtendedMetadata extendedMetadata = metadata.getExtendedMetadata(messageContext.getPeerEntityMetadata().getEntityID());
        messageContext.setPeerExtendedMetadata(extendedMetadata);


        messageContext.peerExtendedMetadata.supportUnsolicitedResponse = true;
        SAMLAuthenticationToken token = new SAMLAuthenticationToken(messageContext)

        replayMock(messageStorage, nameID, assertionobj);

        return token

    }

    private void replayMock(SAMLMessageStorage messageStorage, NameID nameID, Assertion assertion) {

        replay(messageStorage);
        replay(nameID);
        replay(assertion);
    }


    public
    final Assertion buildAssertion(String UdcID, boolean issuerFlag, XMLObjectBuilderFactory builderFactory) throws IllegalStateException {
        AuthnContextClassRef authnContextClassRef = ((SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
                .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME))
                .buildObject();
        authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

        AuthnContext authnContext = ((SAMLObjectBuilder<AuthnContext>) builderFactory
                .getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME)).buildObject();
        authnContext.setAuthnContextClassRef(authnContextClassRef);

        AuthnStatement authStatement = ((SAMLObjectBuilder<AuthnStatement>) builderFactory
                .getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME)).buildObject();
        authStatement.setAuthnContext(authnContext);
        authStatement.setAuthnInstant(new DateTime());


        Conditions conditions = ((SAMLObjectBuilder<Conditions>) builderFactory
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME)).buildObject();
        conditions.setNotBefore(new DateTime());
        conditions.setNotOnOrAfter(new DateTime()
                .plusSeconds(120));

        Audience audience = ((SAMLObjectBuilder<Audience>) builderFactory
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME)).buildObject()
        audience.setAudienceURI("test");

        AudienceRestriction audienceRestrictions = ((SAMLObjectBuilder<AudienceRestriction>) builderFactory
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME)).buildObject()
        audienceRestrictions.getAudiences().add(audience);

        conditions.getAudienceRestrictions().add(audienceRestrictions);

        Issuer issuer = ((SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
        if (issuerFlag) {
            issuer.setValue("abc");
        } else {
            issuer.setValue("localhost:default:entityId");
        }

        Assertion assertion = ((SAMLObjectBuilder<Assertion>) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME)).buildObject();
        assertion.setIssuer(issuer);

        assertion.setIssueInstant(new DateTime());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setID(generateId());
        assertion.getAuthnStatements().add(authStatement);
        assertion.setConditions(conditions);
        assertion.setSubject(buildSubject(builderFactory));

        AttributeStatement attributeStatement = buildAttributeStatement(UdcID, builderFactory);
        if (attributeStatement != null) {
            assertion.getAttributeStatements().add(attributeStatement);
        }
        return assertion;
    }

    private Subject buildSubject(XMLObjectBuilderFactory builderFactory) {
        NameID nameId = ((SAMLObjectBuilder<NameID>) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
        nameId.setValue("TEST");


        SubjectConfirmationData subjectConfirmationData = ((SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
                .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME))
                .buildObject();
        subjectConfirmationData.setNotOnOrAfter(new DateTime()
                .plusSeconds(120))
        subjectConfirmationData.setRecipient("http://localhost")

        SubjectConfirmation subjectConfirmation = ((SAMLObjectBuilder<SubjectConfirmation>) builderFactory
                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME))
                .buildObject();
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subjectConfirmation.setMethod("urn:oasis:names:tc:SAML:2.0:cm:bearer")

        Subject subject = ((SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME)).buildObject();
        subject.setNameID(nameId);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        return subject;
    }

    protected String generateId() {
        String id = "_" + Integer.toHexString(new Random().nextInt(Integer.MAX_VALUE)) + "-" + Integer.toHexString(new Random().nextInt(Integer.MAX_VALUE));
        return id;
    }

    protected AttributeStatement buildAttributeStatement(String UdcID, XMLObjectBuilderFactory builderFactory) throws IllegalStateException {

        AttributeStatement attributeStatement = ((SAMLObjectBuilder<AttributeStatement>) builderFactory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME))
                .buildObject();

        XSString udcIDAttributeValue = ((XSStringBuilder) Configuration
                .getBuilderFactory().getBuilder(XSString.TYPE_NAME))
                .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                XSString.TYPE_NAME);
        udcIDAttributeValue.setValue(UdcID);

        Attribute udcIdAttribute = ((SAMLObjectBuilder<Attribute>) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME)).buildObject();
        udcIdAttribute.setName("UDC_IDENTIFIER");
        udcIdAttribute.setNameFormat("urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified");
        udcIdAttribute.getAttributeValues().add(udcIDAttributeValue);

        attributeStatement.getAttributes().add(udcIdAttribute);

        attributeStatement

    }
}
