package com.example.webauthn.storage

import com.example.webauthn.models.WebAuthCredential
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.RegisteredCredential
import com.yubico.webauthn.RegistrationResult
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import java.time.Instant
import java.util.*
import kotlin.jvm.optionals.getOrNull

class InMemoryRegistrationStorage : CredentialRepository {
    private val webAuthCredentials = ArrayList<WebAuthCredential>()

    fun storeCredential(
        userName: String,
        userHandle: ByteArray,
        result: RegistrationResult,
        pkc: PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
    ) {
        val credential: WebAuthCredential = webAuthCredentials.find { it.userName == userName }
            ?: WebAuthCredential(userName).apply { webAuthCredentials.add(this) }
        credential.userHandle = userHandle
        credential.keyId = result.keyId
        credential.publicKeyCose = result.publicKeyCose
        credential.isDiscoverable = result.isDiscoverable.getOrNull()
        credential.isBackupEligible = result.isBackupEligible
        credential.isBackedUp = result.isBackedUp
        credential.attestationObject = pkc.response.attestationObject
        credential.clientDataJSON = pkc.response.clientDataJSON
    }

    fun updateCredential(
        userName: String,
        signatureCount: Long,
        isBackedUp: Boolean
    ) {
        val credential: WebAuthCredential = webAuthCredentials.find { it.userName == userName }
            ?: throw Exception("User not found")
        credential.signatureCount = signatureCount
        credential.isBackedUp = isBackedUp
        credential.lastTimeOfUse = Instant.now()
    }

    override fun getCredentialIdsForUsername(p0: String?): MutableSet<PublicKeyCredentialDescriptor> {
        val credentials = webAuthCredentials.filter { it.userName == p0 }
        return credentials.map {
            it.keyId!!
        }.toMutableSet()
    }

    override fun getUserHandleForUsername(p0: String?): Optional<ByteArray> {
        val credential = webAuthCredentials.find { it.userName == p0 }
        return Optional.ofNullable(credential?.userHandle)
    }

    override fun getUsernameForUserHandle(p0: ByteArray?): Optional<String> {
        val credential = webAuthCredentials.find { it.userHandle?.compareTo(p0) == 0 }
        return Optional.ofNullable(credential?.userName)
    }

    override fun lookup(p0: ByteArray?, p1: ByteArray?): Optional<RegisteredCredential> {
        val credential = webAuthCredentials.find {
            it.keyId?.id?.compareTo(p0) == 0 && it.userHandle?.compareTo(p1) == 0
        }
        return Optional.ofNullable(credential.let {
            if (it != null) {
                RegisteredCredential.builder()
                    .credentialId(it.keyId!!.id)
                    .userHandle(it.userHandle!!)
                    .publicKeyCose(it.publicKeyCose!!)
                    .signatureCount(it.signatureCount)
                    .build()
            } else {
                null
            }
        })
    }

    override fun lookupAll(p0: ByteArray?): MutableSet<RegisteredCredential> {
        val credentials = webAuthCredentials.filter {
            it.keyId?.id?.compareTo(p0) == 0
        }
        return credentials.map {
            RegisteredCredential.builder()
                .credentialId(it.keyId!!.id)
                .userHandle(it.userHandle!!)
                .publicKeyCose(it.publicKeyCose!!)
                .signatureCount(it.signatureCount)
                .build()
        }.toMutableSet()
    }
}