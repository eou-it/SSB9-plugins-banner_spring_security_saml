import grails.util.Holders
import net.hedtech.banner.security.BannerSamlAuthenticationProvider
import net.hedtech.banner.security.BannerSamlLogoutFilter
import net.hedtech.banner.security.BannerSamlSavedRequestAwareAuthenticationSuccessHandler
import net.hedtech.banner.security.BannerSamlSessionFilter
import net.hedtech.banner.security.BannerSamlSessionRegistryImpl
import grails.plugin.springsecurity.SpringSecurityUtils

class BannerSpringSecuritySamlGrailsPlugin {
    // the plugin version
    def version = "0.1"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "2.5 > *"

    def loadAfter = ['springSecuritySaml','bannerCore']

    def dependsOn = [
            springSecuritySaml: '2.10.2.2 => *',
            bannerCore: '2.10.4 => *'

    ]

    // resources that are excluded from plugin packaging
    def pluginExcludes = [
        "grails-app/views/error.gsp"
    ]

    // TODO Fill in these fields
    def title = "Banner Spring Security Saml Plugin" // Headline display name of the plugin
    def author = "Your name"
    def authorEmail = ""
    def description = '''\
Brief summary/description of the plugin.
'''

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/banner-spring-security-saml"

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

    def doWithSpring = {
        def conf = SpringSecurityUtils.securityConfig

        if (!conf || !conf.saml.active) {
            return
        }

        samlAuthenticationProvider(BannerSamlAuthenticationProvider) {
            userDetails = ref('userDetailsService')
            hokConsumer = ref('webSSOprofileConsumer')
            dataSource = ref(dataSource)
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
    }

    def doWithDynamicMethods = { ctx ->
        // TODO Implement registering dynamic methods to classes (optional)
    }

    def doWithApplicationContext = { ctx ->
        // build providers list here to give dependent plugins a chance to register some
        def conf = SpringSecurityUtils.securityConfig
        if (!conf || !conf.saml.active) {
            return
        }

        def providerNames = []
        if (conf.providerNames) {
            providerNames.addAll conf.providerNames
        } else {
            providerNames = ['samlAuthenticationProvider']
        }
        applicationContext.authenticationManager.providers = createBeanList(providerNames, applicationContext)    }

    def onChange = { event ->
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    def onConfigChange = { event ->
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    def onShutdown = { event ->
        // TODO Implement code that is executed when the application shuts down (optional)
    }

    private def isSsbEnabled() {
        Holders.config.ssbEnabled instanceof Boolean ? Holders.config.ssbEnabled : false
    }

    private createBeanList(names, ctx) { names.collect { name -> ctx.getBean(name) } }

}
