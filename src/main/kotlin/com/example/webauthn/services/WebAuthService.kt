package com.example.webauthn.services

interface WebAuthService {
    fun startRegistration(userName: String): String
    fun finishRegistration(userName: String, publicKeyCredential: String)
    fun startAuthentication(userName: String): String
    fun finishAuthentication(userName: String, authData: String)
}