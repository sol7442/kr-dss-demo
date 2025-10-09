package kr.dss.demo.config;

import eu.europa.esig.dss.utils.Utils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.MappedInterceptor;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${web.security.cookie.samesite}")
    private String samesite;

    @Value("${web.security.csp}")
    private String csp;

    @Value("${web.strict.transport.security:}")
    private String strictTransportSecurity;

    /** API urls (REST/SOAP webServices and server-sign) */
    private static final String[] API_URLS = new String[] {
            "/services/rest/**", "/services/soap/**", "/server-sign/**","/kr-dss/**"
    };

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:5173")); // React dev server
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> {})
            .headers(headers -> {
                headers.addHeaderWriter(serverEsigDSS());
                if (Utils.isStringNotEmpty(strictTransportSecurity)) {
                    headers.addHeaderWriter(strictTransportSecurity());
                }
                if (Utils.isStringNotEmpty(csp)) {
                    headers.contentSecurityPolicy(policy -> policy.policyDirectives(csp));
                }
            })
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    .ignoringRequestMatchers(getAntMatchers()));

        return http.build();
    }

//
    private RequestMatcher[] getAntMatchers() {
        RequestMatcher[] requestMatchers = new RequestMatcher[API_URLS.length];
        for (int i = 0; i < API_URLS.length; i++) {
            requestMatchers[i] = PathPatternRequestMatcher.withDefaults().matcher(API_URLS[i]);
        }
        return requestMatchers;
    }
//
//    @Bean
//    public HeaderWriter javadocHeaderWriter() {
//        final PathPatternRequestMatcher javadocPathRequestMatcher = PathPatternRequestMatcher.withDefaults().matcher("/apidocs/**");
//        final HeaderWriter hw = new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN);
//        return new DelegatingRequestMatcherHeaderWriter(javadocPathRequestMatcher, hw);
//    }
//
//    @Bean
//    public HeaderWriter svgHeaderWriter() {
//        final PathPatternRequestMatcher javadocPathRequestMatcher = PathPatternRequestMatcher.withDefaults().matcher("/validation/diag-data.svg");
//        final HeaderWriter hw = new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN);
//        return new DelegatingRequestMatcherHeaderWriter(javadocPathRequestMatcher, hw);
//    }

    @Bean
    public HeaderWriter serverEsigDSS() {
        return new StaticHeadersWriter("Server", "ESIG-DSS");
    }

    @Bean
    public HeaderWriter strictTransportSecurity() {
        return new StaticHeadersWriter("Strict-Transport-Security", strictTransportSecurity);
    }

    @Bean
    public MappedInterceptor cookiesInterceptor() {
        return new MappedInterceptor(null, new CookiesHandlerInterceptor());
    }

    /**
     * The class is used to enrich "Set-Cookie" header with "SameSite=strict" value
     *
     * NOTE: Spring does not provide support of cookies handling out of the box
     *       and requires a Spring Session dependency for that.
     *       Here is a manual way of response headers configuration
     */
    private final class CookiesHandlerInterceptor implements HandlerInterceptor {

        /** The "SameSite" cookie parameter name */
        private static final String SAMESITE_NAME = "SameSite";

        @Override
        public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                               ModelAndView modelAndView) {
            if (Utils.isStringNotEmpty(samesite)) {
                Collection<String> setCookieHeaders = response.getHeaders(HttpHeaders.SET_COOKIE);
                if (Utils.isCollectionNotEmpty(setCookieHeaders)) {
                    for (String header : setCookieHeaders) {
                        header = String.format("%s; %s=%s", header, SAMESITE_NAME, samesite);
                        response.setHeader(HttpHeaders.SET_COOKIE, header);
                    }
                }
            }
        }
    }

    @Bean
    public RequestRejectedHandler requestRejectedHandler() {
        // Transforms Tomcat interrupted exceptions to a BAD_REQUEST error
        return new RequestRejectedHandler() {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response,
                               RequestRejectedException requestRejectedException) throws IOException {
                LOG.error("An error occurred : " + requestRejectedException.getMessage(), requestRejectedException);
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().println("Bad request : " + requestRejectedException.getMessage());
            }
        };
    }

    @Bean
    public AuthenticationManager noAuthenticationManager() {
        return authentication -> {
            throw new AuthenticationServiceException("Authentication is disabled");
        };
    }

}
