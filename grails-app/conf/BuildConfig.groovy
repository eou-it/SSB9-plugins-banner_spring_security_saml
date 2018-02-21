/*********************************************************************************
 Copyright 2015-2018 Ellucian Company L.P. and its affiliates.
 **********************************************************************************/
grails.servlet.version = "2.5"
grails.project.class.dir = "target/classes"
grails.project.test.class.dir = "target/test-classes"
grails.project.test.reports.dir = "target/test-reports"

grails.plugin.location.'banner-core' = "../banner_core.git"

grails.project.dependency.resolver = "maven" // or ivy
grails.project.dependency.resolution = {

    inherits("global") {

    }
    log "warn" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
    repositories {
        if (System.properties['PROXY_SERVER_NAME']) {
            mavenRepo "${System.properties['PROXY_SERVER_NAME']}"
        }
        grailsCentral()
        grailsPlugins()
        grailsHome()
        mavenLocal()
        mavenCentral()
        mavenRepo "http://repo.spring.io/milestone/"
    }
    dependencies {
        // specify dependencies here under either 'build', 'compile', 'runtime', 'test' or 'provided' scopes eg.
        // runtime 'mysql:mysql-connector-java:5.1.27'

        compile('org.springframework.security:spring-security-crypto:4.0.1.RELEASE')

        compile('org.springframework.security:spring-security-web:3.2.8.RELEASE')

        compile ("org.springframework.security.extensions:spring-security-saml2-core:1.0.1.RELEASE") {
            export = false
        }

        compile ('org.bouncycastle:bcprov-jdk15on:1.59')
        compile('org.owasp.esapi:esapi:2.1.0') {
            excludes 'antisamy', 'bsh-core', 'commons-beanutils-core', 'commons-collections', 'commons-configuration', 'commons-fileupload', 'commons-io', 'jsp-api', 'junit', 'log4j', 'servlet-api', 'xom'
        }
        compile('org.opensaml:xmltooling:1.4.4')
    }

    plugins {
        compile (":spring-security-saml:2.0.1"){
            excludes 'bcprov-jdk15','xmltooling'
        }
    }
}
