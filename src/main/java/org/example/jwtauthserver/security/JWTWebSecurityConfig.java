package org.example.jwtauthserver.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

@Configuration
@EnableWebSecurity
public class JWTWebSecurityConfig {

    @Autowired
    @Qualifier("CustomUserDetailsService")
    private UserDetailsService userDetailsService;

    @Value("${sicurezza.uri}")
    private String authenticationPath;

    @Value("${sicurezza.refresh}")
    private String refreshPath;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Usa NoOpPasswordEncoder per disabilitare la criptazione della password
        // Punto da implementare
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disabilita CSRF poiché JWT non utilizza sessioni
                .csrf(csrf -> csrf.disable())

                // Definisci la gestione delle sessioni come stateless
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configura la protezione delle richieste
                .authorizeHttpRequests(auth -> auth
                        // Permetti accesso senza autenticazione per l'endpoint di login
                        .requestMatchers(HttpMethod.POST, authenticationPath).permitAll()

                        // Permetti le richieste OPTIONS (preflight per CORS)
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // Permetti accesso senza autenticazione all'endpoint di refresh token
                        .requestMatchers(HttpMethod.GET, refreshPath).permitAll()

                        // Permetti l'accesso a qualsiasi richiesta verso /error
                        .requestMatchers("/error").permitAll()

                        // Tutte le altre richieste devono essere autenticate
                        .anyRequest().authenticated()
                )

                // Configura la gestione delle eccezioni per gli utenti non autenticati
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new Http403ForbiddenEntryPoint())
                );

        return http.build();
    }
}
