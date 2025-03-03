package com.example.webauthn.models.request

data class RegistrationFinishRequest(
    var userName: String = "",
    var publicKeyCredential: String = ""
)
