package banner.spring.security.saml

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugins.Plugin
import grails.util.Holders
import net.hedtech.banner.security.*

//TODO ControllerUtils: To be uncomment after adding Banner_core dependency
//import net.hedtech.banner.controllers.ControllerUtils
//TODO Optimize the imports of open saml.
import org.springframework.security.saml.*
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.Filter

class BannerSpringSecuritySamlGrailsPlugin extends Plugin {


    def version = "9.27"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "3.3.2 > *"
    def dependsOn = [
            bannerCore: '9.28.1 => *',
            springSecuritySaml: '3.3.0 => *'
    ]


    // resources that are excluded from plugin packaging
    def pluginExcludes = [
            "grails-app/views/error.gsp"
    ]

    // TODO Fill in these fields
    def title = "Banner Spring Security Saml" // Headline display name of the plugin
    def author = "Your name"
    def authorEmail = ""
    def description = '''\
Brief summary/description of the plugin.
'''
    def profiles = ['web']

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/banner-spring-security-saml"

    // Extra (optional) plugin metadata

    // License: one of 'APACHE', 'GPL2', 'GPL3'
//    def license = "APACHE"

    // Details of company behind the plugin (if there is one)
//    def organization = [ name: "My Company", url: "http://www.my-company.com/" ]

    // Any additional developers beyond the author specified above.
//    def developers = [ [ name: "Joe Bloggs", email: "joe@bloggs.net" ]]

    // Location of the plugin's issue tracker.
//    def issueManagement = [ system: "JIRA", url: "http://jira.grails.org/browse/GPMYPLUGIN" ]

    // Online location of the plugin's browseable source code.
//    def scm = [ url: "http://svn.codehaus.org/grails-plugins/" ]

    //TODO:: doWithWebDescriptor method signature is changed and need to modify this.
    /*
    def doWithWebDescriptor = { xml ->
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.saml.active) {
            return
        }

        def listenerElements = xml.'listener'[0]
        listenerElements + {
            'listener' {
                'display-name'("Http Session Listener")
                'listener-class'("net.hedtech.banner.security.SessionCounterListener")
            }
        }
    }
    */

    Closure doWithSpring() { {->
        // TODO Implement runtime spring config (optional)
        def conf = SpringSecurityUtils.securityConfig

        if (!conf || !conf.saml.active) {
            return
        }

        println '\nConfiguring Banner Spring Security SAML ...'

        samlAuthenticationProvider(BannerSamlAuthenticationProvider) {
            userDetails = ref('userDetailsService')
            hokConsumer = ref('webSSOprofileConsumer')
            dataSource = ref(dataSource)
        }

        bannerSamlAuthenticationFailureHandler(BannerSamlAuthenticationFailureHandler){
            defaultFailureUrl = conf.failureHandler.defaultFailureUrl
        }

        samlProcessingFilter(SAMLProcessingFilter) {
            authenticationManager = ref('authenticationManager')
            authenticationSuccessHandler = ref('successRedirectHandler')
            sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
            authenticationFailureHandler = ref('bannerSamlAuthenticationFailureHandler')
        }

        samlLogoutFilter(BannerSamlLogoutFilter,
                ref('successLogoutHandler'), ref('logoutHandler'), ref('logoutHandler'))

        samlSessionRegistry(BannerSamlSessionRegistryImpl)

        samlSessionFilter(BannerSamlSessionFilter){
            sessionRegistry = ref("samlSessionRegistry")
            contextProvider=ref("contextProvider")
        }
        successRedirectHandler(BannerSamlSavedRequestAwareAuthenticationSuccessHandler) {
            alwaysUseDefaultTargetUrl = conf.saml.alwaysUseAfterLoginUrl ?: false
            defaultTargetUrl = conf.saml.afterLoginUrl
            sessionRegistry = ref("samlSessionRegistry")
        }
        println '...finished configuring Banner Spring Security SAML\n'
    }
    }

    void doWithDynamicMethods() {
        // TODO Implement registering dynamic methods to classes (optional)
    }

    void doWithApplicationContext() {
        // TODO Implement post initialization spring config (optional)
        // build providers list here to give dependent plugins a chance to register some
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.saml.active) {
            return
        }

        def providerNames = []
        if (conf.providerNames) {
            providerNames.addAll conf.providerNames
        } else {
            //TODO ControllerUtils: To be uncomment after adding Banner_core dependency
            /*if(ControllerUtils.isGuestAuthenticationEnabled()){
                providerNames = ['samlAuthenticationProvider','selfServiceBannerAuthenticationProvider','bannerAuthenticationProvider']
            } else{*/
            providerNames = ['samlAuthenticationProvider']
            /*}*/
        }
        applicationContext.authenticationManager.providers = createBeanList(providerNames, applicationContext)

        // Define the spring security filters
        def authenticationProvider = Holders?.config?.banner.sso.authenticationProvider
        LinkedHashMap<String, String> filterChain = new LinkedHashMap();
        switch (authenticationProvider) {
            case 'saml':
                filterChain['/**/api/**'] = 'statelessSecurityContextPersistenceFilter,bannerMepCodeFilter,authenticationProcessingFilter,basicAuthenticationFilter,securityContextHolderAwareRequestFilter,anonymousProcessingFilter,basicExceptionTranslationFilter,filterInvocationInterceptor'
                filterChain['/**/qapi/**'] = 'statelessSecurityContextPersistenceFilter,bannerMepCodeFilter,authenticationProcessingFilter,basicAuthenticationFilter,securityContextHolderAwareRequestFilter,anonymousProcessingFilter,basicExceptionTranslationFilter,filterInvocationInterceptor'
                filterChain['/**'] = 'samlSessionFilter,securityContextPersistenceFilter,bannerMepCodeFilter,samlEntryPoint,metadataFilter,samlProcessingFilter,samlLogoutFilter,samlLogoutProcessingFilter,logoutFilter,authenticationProcessingFilter,securityContextHolderAwareRequestFilter,anonymousProcessingFilter,exceptionTranslationFilter,filterInvocationInterceptor'
                break
            default:
                break
        }

        LinkedHashMap<RequestMatcher, List<Filter>> filterChainMap = new LinkedHashMap()
        filterChain.each { key, value ->
            def filters = value.toString().split(',').collect {
                name -> applicationContext.getBean(name)
            }
            filterChainMap[new AntPathRequestMatcher(key)] = filters
        }
        applicationContext.springSecurityFilterChain.filterChainMap = filterChainMap

    }

    void onChange(Map<String, Object> event) {
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    void onConfigChange(Map<String, Object> event) {
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    void onShutdown(Map<String, Object> event) {
        // TODO Implement code that is executed when the application shuts down (optional)
    }

    private def isSsbEnabled() {
        Holders.config.ssbEnabled instanceof Boolean ? Holders.config.ssbEnabled : false
    }

    private createBeanList(names, ctx) { names.collect { name -> ctx.getBean(name) } }
}
