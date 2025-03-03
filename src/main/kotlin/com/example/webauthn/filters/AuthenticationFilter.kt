package com.example.webauthn.filters

import com.example.webauthn.models.security.AuthPrincipal
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter

class AuthenticationFilter : OncePerRequestFilter() {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val headerNames = request.headerNames.toList().toMutableList()
        headerNames.joinToString("\n") { "$it = ${request.getHeader(it)}" }.also {
            log.info("${request.method} ${request.requestURI} \n${it}")
        }

        val principal = AuthPrincipal()
        SecurityContextHolder.getContext().authentication = principal
        filterChain.doFilter(request, response)
    }
}