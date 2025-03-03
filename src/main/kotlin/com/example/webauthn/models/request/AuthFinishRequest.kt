package com.example.webauthn.models.request

data class AuthFinishRequest(
    var userName: String = "",
    var authData: String = ""
)
