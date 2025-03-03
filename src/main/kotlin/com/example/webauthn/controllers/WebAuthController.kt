package com.example.webauthn.controllers

import com.example.webauthn.models.request.AuthFinishRequest
import com.example.webauthn.models.request.RegistrationFinishRequest
import com.example.webauthn.services.WebAuthService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/webauth/*")
class WebAuthController(
    private val webAuthService: WebAuthService
) {
    @GetMapping("/registration/start")
    fun registrationStart(@RequestParam login: String): ResponseEntity<String> {
        val response = webAuthService.startRegistration(login)
        return ResponseEntity(response, HttpStatus.OK)
    }

    @PostMapping("/registration/finish")
    fun registrationFinish(@RequestBody registrationFinishRequest: RegistrationFinishRequest): ResponseEntity<String> {
        webAuthService.finishRegistration(
            registrationFinishRequest.userName,
            registrationFinishRequest.publicKeyCredential
        )
        return ResponseEntity("OK", HttpStatus.OK)
    }

    @GetMapping("/auth/start")
    fun authStart(@RequestParam login: String): ResponseEntity<String> {
        val response = webAuthService.startAuthentication(login)
        return ResponseEntity(response, HttpStatus.OK)
    }

    @PostMapping("/auth/finish")
    fun authFinish(@RequestBody authFinishRequest: AuthFinishRequest): ResponseEntity<String> {
        webAuthService.finishAuthentication(
            authFinishRequest.userName,
            authFinishRequest.authData
        )
        return ResponseEntity("OK", HttpStatus.OK)
    }
}