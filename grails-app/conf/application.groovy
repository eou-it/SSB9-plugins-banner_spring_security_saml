/*******************************************************************************
 Copyright 2015-2018 Ellucian Company L.P. and its affiliates.
 *******************************************************************************/
dataSource {
    dialect = "org.hibernate.dialect.Oracle10gDialect"
    loggingSql = false
}


hibernate {
    cache.use_second_level_cache = false
    cache.use_query_cache = false
    cache.region.factory_class = 'org.hibernate.cache.ehcache.EhCacheRegionFactory'
    //hbm2ddl.auto = null
    show_sql = false
    packagesToScan="net.hedtech.**.*"
    flush.mode = AUTO
}

environments {
    test {
        grails.plugin.springsecurity.saml.active = false
    }
}

//Added for integration tests to run in plugin level
grails.config.locations = [
        BANNER_APP_CONFIG: "banner_configuration.groovy"
]