package com.example.Java.Spring.Security.Configuration;

import com.example.Java.Spring.Security.Filter.JwtFilter;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
@NoArgsConstructor
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration {
    // Injecting custom authentication provider for handling user credentials
    @Autowired
    private AuthenticationProvider authenticationProvider;

    // Injecting custom JWT filter to intercept requests and validate tokens
    @Autowired
    private JwtFilter jwtFilter;

    // Defining the security filter chain for the application
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Disable CSRF since this is a stateless REST API using JWT
                .csrf(AbstractHttpConfigurer::disable)
                // Configure URL-based access rules
                .authorizeHttpRequests(req ->req
                        // Allow all requests to auth endpoints (login, register, etc.)
                        .requestMatchers("/api/v1/auth/*")
                        .permitAll()
                        .requestMatchers("/admin/api/**").hasRole("ADMIN")
                        .requestMatchers("/hr/api/**").hasAnyRole("HR","ADMIN")
                )
                // Set session management to stateless (no HTTP session will be used)
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                // Use the custom authentication provider for authentication logic
                .authenticationProvider(authenticationProvider)
                // Add the custom JWT filter before the default UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                // Build and return the configured security filter chain
                .build();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**") // allow all endpoints
                        .allowedOrigins("http://localhost:5173/") // your frontend port
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true);
            }
        };
    }

}
