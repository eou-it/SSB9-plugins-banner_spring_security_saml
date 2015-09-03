grails.servlet.version = "2.5"
grails.project.class.dir = "target/classes"
grails.project.test.class.dir = "target/test-classes"
grails.project.test.reports.dir = "target/test-reports"

grails.plugin.location.'spring-security-saml'      = "../spring_security_saml.git"
grails.plugin.location.'banner-core' = "../banner_core.git"

grails.project.dependency.resolver = "maven" // or ivy
grails.project.dependency.resolution = {

    inherits("global") {

    }
    log "warn" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
    repositories {
        grailsCentral()
        mavenLocal()
        mavenCentral()
    }
    dependencies {
        // specify dependencies here under either 'build', 'compile', 'runtime', 'test' or 'provided' scopes eg.
        // runtime 'mysql:mysql-connector-java:5.1.27'
        compile('org.springframework.security:spring-security-crypto:4.0.1.RELEASE')

        compile('org.springframework.security:spring-security-web:3.2.8.RELEASE')

        compile ("org.springframework.security.extensions:spring-security-saml2-core:1.0.1.RELEASE") {
            export = false
        }
    }

    plugins {
        runtime  ":hibernate:3.6.10.19"
    }
}
