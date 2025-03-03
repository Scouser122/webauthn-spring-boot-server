package com.example.webauthn.services

import com.example.webauthn.storage.InMemoryRegistrationStorage
import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.AssertionResult
import com.yubico.webauthn.FinishAssertionOptions
import com.yubico.webauthn.FinishRegistrationOptions
import com.yubico.webauthn.RegistrationResult
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.StartAssertionOptions
import com.yubico.webauthn.StartRegistrationOptions
import com.yubico.webauthn.data.*
import org.apache.catalina.User
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.util.Random

@Service
class WebAuthServiceLib : WebAuthService {
    private val users = ArrayList<UserIdentity>()
    private val random = Random()
    private val registrationRequests: HashMap<String, PublicKeyCredentialCreationOptions> = hashMapOf()
    private val authenticationRequests: HashMap<String, AssertionRequest> = hashMapOf()
    private val logger = LoggerFactory.getLogger(javaClass)
    private val registrationStorage = InMemoryRegistrationStorage()

    private val relyingParty: RelyingParty = let {
        val rpIdentity = RelyingPartyIdentity.builder()
            .id("scouser122.online")
            .name("scouser122")
            .build()

        RelyingParty.builder()
            .identity(rpIdentity)
            .credentialRepository(registrationStorage)
            .origins(setOf("localhost", "http://localhost:1234", "https://scouser122.online"))
            .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
            .build()
    }

    override fun startRegistration(userName: String): String {
        val user = findExistingUser(userName) ?: createNewUser(userName)
        val request = relyingParty.startRegistration(
            StartRegistrationOptions.builder()
                .user(user)
                .authenticatorSelection(
                    AuthenticatorSelectionCriteria.builder()
                        .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                        .residentKey(ResidentKeyRequirement.PREFERRED)
                        .userVerification(UserVerificationRequirement.PREFERRED)
                        .build()
                )
                .extensions(
                    RegistrationExtensionInputs.builder()
                        .credProps()
                        .largeBlob(Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport.PREFERRED)
                        .build()
                )
                .timeout(60000)
                .build()
        )
        val credentialCreateJSON = request.toCredentialsCreateJson()
        registrationRequests[userName] = request
        return credentialCreateJSON
    }

    override fun finishRegistration(userName: String, publicKeyCredential: String) {
        val user = findExistingUser(userName) ?: throw Exception("User not found")
        val pkc = PublicKeyCredential.parseRegistrationResponseJson(publicKeyCredential)
        val request = registrationRequests[userName]
        val finishRegistrationOptions = FinishRegistrationOptions.builder()
            .request(request)
            .response(pkc)
            .build()
        try {
            val result: RegistrationResult = relyingParty.finishRegistration(finishRegistrationOptions)
            registrationStorage.storeCredential(
                userName, user.id, result, pkc
            )
        } catch (ex: Exception) {
            logger.error(ex.message, ex)
            throw ex
        }
    }

    override fun startAuthentication(userName: String): String {
        findExistingUser(userName) ?: throw Exception("User not found")
        val request: AssertionRequest = relyingParty.startAssertion(
            StartAssertionOptions.builder()
                .username(userName)
                .userVerification(UserVerificationRequirement.PREFERRED)
                .build()
        )
        val credentialGetJson = request.toCredentialsGetJson()
        authenticationRequests[userName] = request
        return credentialGetJson
    }

    override fun finishAuthentication(userName: String, authData: String) {
        val pkc = PublicKeyCredential.parseAssertionResponseJson(authData)
        val request = authenticationRequests[userName]
        try {
            val result: AssertionResult = relyingParty.finishAssertion(
                FinishAssertionOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build()
            )
            if (!result.isSuccess) {
                throw RuntimeException("Authentication failed")
            }
            registrationStorage.updateCredential(
                userName,
                result.signatureCount,
                result.isBackedUp
            )
        } catch (ex: Exception) {
            logger.error(ex.message, ex)
            throw ex
        }
    }

    fun findExistingUser(userName: String): UserIdentity? {
        return users.find { it.name == userName }
    }

    fun createNewUser(userName: String): UserIdentity {
        val userHandle = ByteArray(32)
        random.nextBytes(userHandle)
        val newUser = UserIdentity.builder()
            .name(userName)
            .displayName(userName)
            .id(com.yubico.webauthn.data.ByteArray(userHandle))
            .build()
        users.add(newUser)
        return newUser
    }
}