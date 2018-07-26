// TODO configuration for plugin testing - will not be included in the plugin zip
/*******************************************************************************
 Copyright 2015-2018 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
//TODO Commenting the imports and corresponding changes as imports in not supported here

// ******************************************************************************
//
//                       +++ EXTERNALIZED CONFIGURATION +++
//
// ******************************************************************************

grails.config.locations = [] // leave this initialized to an empty list, and add your locations in the map below.
//TODO Commenting the imports and corresponding changes as imports in not supported here

grails.config.locations.each {
       println "configuration: " + it
}


//DataSource.groovy migrated


hibernate {
       cache.use_second_level_cache = false
       cache.use_query_cache = false
       cache.provider_class = 'org.hibernate.cache.EhCacheProvider'
}


