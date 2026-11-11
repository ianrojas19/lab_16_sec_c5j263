package ucr.ac.cr.medivault.security;

import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config
    .annotation.method.configuration
    .EnableMethodSecurity;
import org.springframework.security.config
    .annotation.web.builders.HttpSecurity;
import org.springframework.security.config
    .annotation.web.configuration
    .EnableWebSecurity;
import org.springframework.security.config
    .annotation.web.configurers.*;
import org.springframework.security.config
    .http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt
    .BCryptPasswordEncoder;
import org.springframework.security.crypto.password
    .PasswordEncoder;
import org.springframework.security.web
    .SecurityFilterChain;
import org.springframework.security.web
    .authentication
    .UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher
    .AnyRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final RateLimitingFilter rateFilter;

    public SecurityConfig(
            JwtAuthenticationFilter jwtFilter,
            RateLimitingFilter rateFilter) {
        this.jwtFilter = jwtFilter;
        this.rateFilter = rateFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http) throws Exception {
        http
            // 1. Desactivacion CSRF (Stateless JWT)
            .csrf(AbstractHttpConfigurer::disable)

            // 2. Sesion sin estado (Stateless)
            .sessionManagement(s -> s
                .sessionCreationPolicy(
                    SessionCreationPolicy.STATELESS
                )
            )

            // 3. Reglas de Autorizacion
            .authorizeHttpRequests(a -> a
                .requestMatchers(
                    HttpMethod.POST,
                    "/api/v1/auth/login"
                ).permitAll()
                .requestMatchers(
                    HttpMethod.HEAD,
                    "/api/v1/auth/login"
                ).permitAll()
                .requestMatchers("/h2-console/**")
                .denyAll()
                .requestMatchers(
                    "/api/v1/expedientes/**")
                .authenticated()
                .anyRequest().authenticated()
            )

            // 4. Hardening de Cabeceras HTTP
            .headers(h -> h
                // Bloquea Clickjacking (no iframes)
                .frameOptions(
                    HeadersConfigurer
                        .FrameOptionsConfig::deny
                )
                // Bloquea MIME-Sniffing
                .contentTypeOptions(
                    Customizer.withDefaults()
                )
                // CSP Nivel 3
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "frame-ancestors 'none'; " +
                        "object-src 'none';"
                    )
                )
                // HSTS: obliga uso de HTTPS
                .httpStrictTransportSecurity(hsts ->
                    hsts.includeSubDomains(true)
                        .maxAgeInSeconds(31536000)
                        .requestMatcher(
                            AnyRequestMatcher.INSTANCE)
                )
                // Prohibe cache de datos medicos
                .cacheControl(
                    Customizer.withDefaults()
                )
            )

            // 5. Insercion de Filtros en Pipeline
            .addFilterBefore(
                rateFilter,
                UsernamePasswordAuthenticationFilter
                    .class
            )
            .addFilterBefore(
                jwtFilter,
                UsernamePasswordAuthenticationFilter
                    .class
            );

        return http.build();
    }
}
