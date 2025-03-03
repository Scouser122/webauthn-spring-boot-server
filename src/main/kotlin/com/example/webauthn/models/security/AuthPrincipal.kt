package com.example.webauthn.models.security

import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import java.io.Serializable

class AuthPrincipal : Authentication, Serializable {
    override fun getName(): String {
        return "test"
    }

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        return listOf<GrantedAuthority>().toMutableList()
    }

    override fun getCredentials(): Any? {
        return null
    }

    override fun getDetails(): Any? {
        return null
    }

    override fun getPrincipal(): Any {
        return "test"
    }

    override fun isAuthenticated(): Boolean {
        return true
    }

    override fun setAuthenticated(isAuthenticated: Boolean) {

    }
}