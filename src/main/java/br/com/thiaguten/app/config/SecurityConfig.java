package br.com.thiaguten.app.config;

import static br.com.thiaguten.app.utils.JwtHelper.AUTHORITIES_CLAIM_NAME;
import static br.com.thiaguten.app.utils.JwtHelper.AUTHORITY_PREFIX;
import static org.springframework.security.config.Customizer.withDefaults;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import br.com.thiaguten.app.user.model.UserRole.AllowedRoles;
import br.com.thiaguten.app.user.service.UserAuthManager;
import br.com.thiaguten.app.user.service.UserService;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${security.debug-enabled:false}")
    private boolean securityDebugEnabled;

    private final RSAPublicKey rsaPublicKey;
    private final RSAPrivateKey rsaPrivateKey;

    // @formatter:off
    public SecurityConfig(
    /* @Value("${security.jwt.rsa-public-key}") RSAPublicKey rsaPublicKey,
       @Value("${security.jwt.rsa-private-key}") RSAPrivateKey rsaPrivateKey */) {
        // this.rsaPublicKey = rsaPublicKey;
        // this.rsaPrivateKey = rsaPrivateKey;

        // FAKE HARDCODED KEYS - IT'S JUST AN EXAMPLE! 
        // DON'T PLACE YOUR KEYS EMBEDDED IN THE PROJECT
        this.rsaPublicKey = TestKeys.DEFAULT_PUBLIC_KEY;
        this.rsaPrivateKey = TestKeys.DEFAULT_PRIVATE_KEY;
    }
    // @formatter:on

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            // Excluir as requisições preflight da autorização.
            // https://docs.spring.io/spring-security/reference/servlet/integrations/cors.html
            .cors(withDefaults())

            // Habilitar CSRF (default).
            // https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html
            .csrf(csrf -> csrf
                // Ignorando proteção CSRF para alguns endpoints.
                // https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html#disable-csrf
                .ignoringAntMatchers("/api/public/v1/users/login", "/api/admin/v1/users")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            
            .authorizeHttpRequests(authorize -> authorize
                // .antMatchers("/actuator/**").permitAll()
                .antMatchers("/api/public/**").permitAll()
                .antMatchers("/api/admin/**").hasRole(AllowedRoles.ADMIN.name())
                .antMatchers("/api/v1/users/**").hasRole(AllowedRoles.USER.name())
                // Qualquer outra solicitação exige que o usuário seja autenticado.
                .anyRequest().authenticated()
            )

            // https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/basic.html
            .httpBasic(withDefaults())

            // https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html
            .oauth2ResourceServer(oauth2 -> oauth2
                // Configura uma customização de conversão do token JWT para obter as ROLES
                // a partir de um claim específico.
                // https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html#oauth2resourceserver-jwt-authorization-extraction
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
        
            // Às vezes, não há necessidade de criar e manter uma HttpSession, por exemplo, 
            // para manter a autenticação entre as solicitações. Alguns mecanismos de autenticação, 
            // como o HTTP Basic, não têm estado e, portanto, autenticam novamente o usuário em cada solicitação.
            // https://docs.spring.io/spring-security/reference/servlet/authentication/session-management.html#stateless-authentication
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Definir como manipular as exceções para solicitações não autorizadas.
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                .accessDeniedHandler(new BearerTokenAccessDeniedHandler()));

        // @formatter:on
        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService(UserService userService) {
        // Implementação que busca um usuário na base de dados para procedimento de
        // autenticação.
        return new UserAuthManager(userService);
    }

    @Bean
    static RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy(
                AUTHORITY_PREFIX + AllowedRoles.ADMIN.getName()
                        + " > " + AUTHORITY_PREFIX + AllowedRoles.USER.getName());
        return hierarchy;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CorsFilter corsFilter() {
        return new CorsFilter(corsConfigurationSource());
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.applyPermitDefaultValues();
        config.setAllowedMethods(Collections.singletonList("*"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    JwtDecoder jwtDecoder() {
        // https://docs.spring.io/spring-security/reference/reactive/oauth2/resource-server/jwt.html#webflux-oauth2resourceserver-jwt-decoder-public-key
        return NimbusJwtDecoder.withPublicKey(this.rsaPublicKey).build();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        RSAKey jwk = new RSAKey.Builder(this.rsaPublicKey).privateKey(this.rsaPrivateKey).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.debug(securityDebugEnabled)
                .ignoring()
                .antMatchers("/css/**", "/js/**", "/img/**", "/lib/**", "/favicon.ico");
    }

    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix(AUTHORITY_PREFIX);
        authoritiesConverter.setAuthoritiesClaimName(AUTHORITIES_CLAIM_NAME);

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return jwtAuthenticationConverter;
    }

}
