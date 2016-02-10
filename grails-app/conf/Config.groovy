// configuration for plugin testing - will not be included in the plugin zip
/*******************************************************************************
 Copyright 2015 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
import net.hedtech.banner.configuration.ApplicationConfigurationUtils

// ******************************************************************************
//
//                       +++ EXTERNALIZED CONFIGURATION +++
//
// ******************************************************************************

grails.config.locations = [] // leave this initialized to an empty list, and add your locations in the map below.
def locationAdder = ApplicationConfigurationUtils.&addLocation.curry(grails.config.locations)
println "App Name ${appName}"
[ BANNER_APP_CONFIG:        "banner_configuration.groovy",
  BANNER_SPRING_SECURITY_SAML_CONFIG: "banner_spring_security_saml_configuration.groovy",
].each { envName, defaultFileName -> locationAdder( envName, defaultFileName ) }
grails.config.locations.each {
       println "configuration: " + it
}

log4j = {
    // Example of changing the log pattern for the default console
    // appender:
    //
    //appenders {
    //    console name:'stdout', layout:pattern(conversionPattern: '%c{2} %m%n')
    //}

    error  'org.codehaus.groovy.grails.web.servlet',  //  controllers
           'org.codehaus.groovy.grails.web.pages', //  GSP
           'org.codehaus.groovy.grails.web.sitemesh', //  layouts
           'org.codehaus.groovy.grails.web.mapping.filter', // URL mapping
           'org.codehaus.groovy.grails.web.mapping', // URL mapping
           'org.codehaus.groovy.grails.commons', // core / classloading
           'org.codehaus.groovy.grails.plugins', // plugins
           'org.codehaus.groovy.grails.orm.hibernate', // hibernate integration
           'org.springframework',
           'org.hibernate',
           'net.sf.ehcache.hibernate'
}
