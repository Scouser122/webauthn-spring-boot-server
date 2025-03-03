package com.example.webauthn.config

import com.example.webauthn.filters.AuthenticationFilter
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http.authorizeHttpRequests {
            it
                .requestMatchers("/api/**").permitAll()
        }.cors {
            it.configurationSource {
                CorsConfiguration().applyPermitDefaultValues()
            }
        }.csrf {
            it.disable()
        }.addFilterAt(
            AuthenticationFilter(),
            UsernamePasswordAuthenticationFilter::class.java
        )
        return http.build()
    }
}