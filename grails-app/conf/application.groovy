// TODO configuration for plugin testing - will not be included in the plugin zip
/*******************************************************************************
 Copyright 2015-2018 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
//TODO Commenting the imports and corresponding changes as imports in not supported here
//import net.hedtech.banner.configuration.ApplicationConfigurationUtils

// ******************************************************************************
//
//                       +++ EXTERNALIZED CONFIGURATION +++
//
// ******************************************************************************

grails.config.locations = [] // leave this initialized to an empty list, and add your locations in the map below.
//TODO Commenting the imports and corresponding changes as imports in not supported here
/*def locationAdder = ApplicationConfigurationUtils.&addLocation.curry(grails.config.locations)
println "App Name ${appName}"
[ BANNER_APP_CONFIG:        "banner_configuration.groovy",
  BANNER_SPRING_SECURITY_SAML_CONFIG: "banner_spring_security_saml_configuration.groovy",
].each { envName, defaultFileName -> locationAdder( envName, defaultFileName ) }*/
grails.config.locations.each {
       println "configuration: " + it
}

