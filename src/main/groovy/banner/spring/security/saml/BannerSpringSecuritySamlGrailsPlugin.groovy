package banner.spring.security.saml

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.web.GrailsSecurityFilterChain
import grails.plugins.Plugin
import grails.util.Holders
import net.hedtech.banner.controllers.ControllerUtils
import net.hedtech.banner.security.*
import org.springframework.security.saml.*
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.Filter

class BannerSpringSecuritySamlGrailsPlugin extends Plugin {

    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "3.3.2 > *"
    List loadAfter = ['bannerCore', 'bannerGeneralUtility', 'springSecuritySaml']
    def dependsOn = [
            bannerCore          : '9.28.1 => *',
            bannerGeneralUtility: '9.28.1 => *',
            springSecuritySaml  : '3.3.0 => *'

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

    Closure doWithSpring() {
        { ->
            // TODO Implement runtime spring config (optional)
            def conf = SpringSecurityUtils.securityConfig
            println "**********************************In banner SAML conf ********************************************"
            println conf.saml
            println "*****************************************  **********************************************************"

            if (Holders.config.banner?.sso?.authenticationProvider == 'default' || (Holders.config.banner?.sso?.authenticationProvider == 'cas') || (Holders.config.banner?.sso?.authenticationProvider == 'saml' && !conf.saml.active)) {
                //TODO change or remove this below code as now the Open SAML Plugin is executing by default so when the code in Open SAML plugin is change we can remove this
                if (Holders.config.banner?.sso?.authenticationProvider == 'default') {
                    logoutSuccessHandler(SimpleUrlLogoutSuccessHandler) {
                        defaultTargetUrl = Holders.config.grails.plugin.springsecurity.logout.afterLogoutUrl
                    }
                }
                return
            }

            println '\nConfiguring Banner Spring Security SAML ...'

            samlAuthenticationProvider(BannerSamlAuthenticationProvider) {
                userDetails = ref('userDetailsService')
                hokConsumer = ref('webSSOprofileConsumer')
                dataSource = ref(dataSource)
            }

            bannerSamlAuthenticationFailureHandler(BannerSamlAuthenticationFailureHandler) {
                defaultFailureUrl = Holders.config.banner?.sso?.grails?.plugin?.springsecurity?.failureHandler.defaultFailureUrl
            }

            samlProcessingFilter(SAMLProcessingFilter) {
                authenticationManager = ref('authenticationManager')
                authenticationSuccessHandler = ref('successRedirectHandler')
                sessionAuthenticationStrategy = ref('sessionFixationProtectionStrategy')
                authenticationFailureHandler = ref('bannerSamlAuthenticationFailureHandler')
            }

            samlLogoutFilter(BannerSamlLogoutFilter,
                    ref('logoutSuccessHandler'), ref('logoutHandler'), ref('logoutHandler'))

            samlSessionRegistry(BannerSamlSessionRegistryImpl)

            samlSessionFilter(BannerSamlSessionFilter) {
                sessionRegistry = ref("samlSessionRegistry")
                contextProvider = ref("contextProvider")
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

        if (Holders.config.banner?.sso?.authenticationProvider == 'default' || (Holders.config.banner?.sso?.authenticationProvider == 'cas') || (Holders.config.banner?.sso?.authenticationProvider == 'saml' && !conf.saml.active)) {
            return
        }

        def providerNames = []
        if (conf.providerNames) {
            providerNames.addAll conf.providerNames
        } else {
            if (ControllerUtils.isGuestAuthenticationEnabled()) {
                providerNames = ['samlAuthenticationProvider', 'selfServiceBannerAuthenticationProvider', 'bannerAuthenticationProvider']
            } else {
                providerNames = ['samlAuthenticationProvider']
            }
        }
        applicationContext.authenticationManager.providers = createBeanList(providerNames, applicationContext)

        // Define the spring security filters
        def authenticationProvider = Holders?.config?.banner.sso.authenticationProvider
        List<Map<String, ?>> filterChains = []
        switch (authenticationProvider) {
            case 'saml':
                filterChains << [pattern: '/**/api/**', filters: 'statelessSecurityContextPersistenceFilter,bannerMepCodeFilter,authenticationProcessingFilter,basicAuthenticationFilter,securityContextHolderAwareRequestFilter,anonymousProcessingFilter,basicExceptionTranslationFilter,filterInvocationInterceptor']
                filterChains << [pattern: '/**/qapi/**', filters: 'statelessSecurityContextPersistenceFilter,bannerMepCodeFilter,authenticationProcessingFilter,basicAuthenticationFilter,securityContextHolderAwareRequestFilter,anonymousProcessingFilter,basicExceptionTranslationFilter,filterInvocationInterceptor']
                filterChains << [pattern: '/**', filters: 'samlSessionFilter,securityContextPersistenceFilter,bannerMepCodeFilter,samlEntryPoint,metadataFilter,samlProcessingFilter,samlLogoutFilter,samlLogoutProcessingFilter,logoutFilter,authenticationProcessingFilter,securityContextHolderAwareRequestFilter,anonymousProcessingFilter,exceptionTranslationFilter,filterInvocationInterceptor']

                break
            default:
                break
        }
        List<GrailsSecurityFilterChain> chains = new ArrayList<GrailsSecurityFilterChain>()
        for (Map<String, ?> entry in filterChains) {
            println " FilterChains Entry in SAML === " + entry
            String value = (entry.filters ?: '').toString().trim()
            List<Filter> filters = value.toString().split(',').collect { String name -> applicationContext.getBean(name, Filter) }
            chains << new GrailsSecurityFilterChain(entry.pattern as String, filters)
        }
        applicationContext.springSecurityFilterChain.filterChains = chains
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
