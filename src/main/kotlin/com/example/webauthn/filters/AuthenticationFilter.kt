package com.example.webauthn.filters

import com.example.webauthn.models.security.AuthPrincipal
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter

class AuthenticationFilter : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val principal = AuthPrincipal()
        SecurityContextHolder.getContext().authentication = principal
        filterChain.doFilter(request, response)
    }
}