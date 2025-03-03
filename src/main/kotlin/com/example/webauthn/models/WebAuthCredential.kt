package com.example.webauthn.models

import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import java.time.Instant

data class WebAuthCredential (
    var userName: String = "",
    var userHandle: ByteArray? = null,
    var keyId: PublicKeyCredentialDescriptor? = null,
    var publicKeyCose: ByteArray? = null,
    var signatureCount: Long = 0L,
    var isDiscoverable: Boolean? = false,
    var isBackupEligible: Boolean = false,
    var isBackedUp: Boolean = false,
    var attestationObject: ByteArray? = null,
    var clientDataJSON: ByteArray? = null,
    var lastTimeOfUse: Instant? = null
)