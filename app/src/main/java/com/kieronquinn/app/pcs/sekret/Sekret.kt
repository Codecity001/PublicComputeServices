package com.kieronquinn.app.pcs.sekret

import java.security.MessageDigest

object Sekret {

    @JvmStatic
    private external fun _manifestKeyEncrypted(): IntArray?

    @JvmStatic
    private external fun manifestKeyDecrypted(key: String): String?

    fun manifestKey(key: String): String? {
        val encrypted = _manifestKeyEncrypted()?.takeIf { it.isNotEmpty() }
            ?: return manifestKeyDecrypted(key)
        val sha256Hex = MessageDigest.getInstance("SHA-256")
            .digest(key.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
            .toByteArray(Charsets.UTF_8)
        val decrypted = ByteArray(encrypted.size) { index ->
            val k = sha256Hex[index % sha256Hex.size].toInt()
            val e = encrypted[index].toByte().toInt()
            (k xor e).toByte()
        }
        return decrypted.decodeToString()
    }

}
