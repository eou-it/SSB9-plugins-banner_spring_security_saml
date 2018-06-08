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


//DataSource.groovy migrated
dataSource {
       pooled = true
       driverClassName = 'org.h2.Driver'
       username = 'sa'
       password = ''
       dbCreate = 'update'
       url = 'jdbc:h2:mem:testDb'
}

hibernate {
       cache.use_second_level_cache = false
       cache.use_query_cache = false
       cache.provider_class = 'org.hibernate.cache.EhCacheProvider'
}


// environment specific settings
environments {
       development {
              dataSource {
                     dbCreate = "create-drop" // one of 'create', 'create-drop', 'update', 'validate', ''
                     url = "jdbc:h2:mem:devDb;MVCC=TRUE;LOCK_TIMEOUT=10000"
              }
       }
       test {
              dataSource {
                     dbCreate = "update"
                     url = "jdbc:h2:mem:testDb;MVCC=TRUE;LOCK_TIMEOUT=10000"
              }
       }
       production {
              dataSource {
                     dbCreate = "update"
                     url = "jdbc:h2:prodDb;MVCC=TRUE;LOCK_TIMEOUT=10000"
                     pooled = true
                     properties {
                            maxActive = -1
                            minEvictableIdleTimeMillis=1800000
                            timeBetweenEvictionRunsMillis=1800000
                            numTestsPerEvictionRun=3
                            testOnBorrow=true
                            testWhileIdle=true
                            testOnReturn=true
                            validationQuery="SELECT 1"
                     }
              }
       }
}

