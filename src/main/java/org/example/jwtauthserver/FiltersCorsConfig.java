package org.example.jwtauthserver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class FiltersCorsConfig implements WebMvcConfigurer {

    @Bean
    WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:4200")
                        .allowedMethods("POST", "GET", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH")
                        .allowedOrigins("*")
                        .exposedHeaders("header1", "header2", "Authorization")
                        .allowCredentials(false)
                        .maxAge(3600);

            }
        };
    }
}