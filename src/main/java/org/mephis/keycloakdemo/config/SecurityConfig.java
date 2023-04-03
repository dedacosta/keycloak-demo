package org.mephis.keycloakdemo.config;

import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

@Log
@Configuration
@EnableMethodSecurity
public class SecurityConfig {


    @Value("${cors.allowed-origins}")
    private String[] allowedOrigins;

    // https://docs.spring.io/spring-security/reference/6.1/servlet/integrations/cors.html#page-title
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        log.info("CORS Allowed Origins: " + Arrays.toString(allowedOrigins));
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedHeaders(Arrays.asList("Access-Control-Allow-Headers", "Origin", "Content-Type", "Accept", "Authorization"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "OPTIONS", "DELETE", "PATCH"));
        configuration.setAllowedOrigins(Arrays.asList(this.allowedOrigins));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .anyRequest()
                .authenticated());
        http.oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(grantedAuthoritiesExtractor());
        http.cors(Customizer.withDefaults());
        return http.build();
    }

    private Converter<Jwt, AbstractAuthenticationToken> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new GrantedAuthoritiesExtractor());
        return jwtAuthenticationConverter;
    }

    static class GrantedAuthoritiesExtractor implements Converter<Jwt, Collection<GrantedAuthority>> {
        @SuppressWarnings("unchecked")
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            return (
                    (Map<String, Collection<?>>) jwt.getClaims().getOrDefault("realm_access", Collections.emptyMap())
            ).getOrDefault("roles", Collections.emptyList())
                    .stream()
                    .map(Object::toString)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
    }

}
