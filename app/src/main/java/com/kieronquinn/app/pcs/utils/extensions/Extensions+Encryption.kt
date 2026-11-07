package com.kieronquinn.app.pcs.utils.extensions

import android.content.Context
import android.content.pm.PackageManager
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.kieronquinn.app.pcs.BuildConfig
import com.kieronquinn.app.pcs.sekret.Sekret

fun Context.getManifestKey(): KeysetHandle {
    val key = Sekret.manifestKey(getSignatureHash().toHexString())?.hexToByteArray()
    return key?.toKeysetHandle() ?: throw IllegalStateException("Unable to load manifest key")
}

fun ByteArray.toKeysetHandle(): KeysetHandle {
    return CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(this))
}

/**
 *  Decrypt a manifest with a given keyset handle. If a [Context] is passed, the signature of the
 *  **module** will be used as the context info, if `null` then an empty array will be used.
 */
fun ByteArray.decryptManifest(context: Context?, key: KeysetHandle): ByteArray {
    val contextInfo = context?.getSignatureHash() ?: byteArrayOf()
    return key.getPrimitive(
        RegistryConfiguration.get(),
        HybridDecrypt::class.java
    ).decrypt(this, contextInfo)
}

private const val OFFICIAL_SIGNATURE_HEX =
    "308202cf308201b7a0030201020204055c8983300d06092a864886f70d01010b05003017311530130603550403130c4b" +
    "6965726f6e205175696e6e3020170d3132303831333138333932325a180f32313132303732303138333932325a301731" +
    "1530130603550403130c4b6965726f6e205175696e6e30820122300d06092a864886f70d01010105000382010f003082" +
    "010a028201010083c7dcd8bd190546b8be46c6293e461e3f5528fff43d914c1165c5d3d771ab4ba16eb43e4ba215e5e5" +
    "6d13ce932c6628bbfdcbb22d2787964ffc30c41d657cbccf724dfdb793cea890935e6f2d7e27b0b8534bb8cdbb637161" +
    "0e5cea7f5da76631ec7c8a05f5ad8a63460f5c11a6bf83e527f32cdc7a9698843028353213db462d47eb1af4280cd47e" +
    "038eaee46abb91769fb946de5bd2f72dcf40e0830ce3a25521dcc9a368bc0f958916dde8750db6f92209cb60b7b24080" +
    "523a95c6d61dce26a9805b2fbe5e8fb301cf1834eea287bd89ca040be0aba2546b88e03aa3fe44751d9e8f9adc2a4595" +
    "dbb2f3619d79ab2e19b0e834842dd5ffc1a93d12b78a830203010001a321301f301d0603551d0e041604142fd901c591" +
    "e0c7ce2d4102d98393138dd258ff47300d06092a864886f70d01010b050003820101006ead13a67b102fe68e390bc827" +
    "baab5db59bbc750dc8ffe563c82b41b570b5dcf86ca7ff5200785cf913143230dbba6eaa4168a0bbbe87f173c006a3d4" +
    "faee0a054b7fe5450164b32b76d0f0bd8e087b6f2eb9f1867a8ba53e58c668d258d325ba058d7f7ae31d99aa38435251" +
    "e489956089aee7a2b23eada5f54933a5aeac9de9ad3caf661ee28ada7f9f5c8a913fe093c342a75009b6477ed439d193" +
    "21002cb1132ae74eeb75d7b777c9999302fe5a5062c6bfeeffeface4e583ca10672ee8ee6bc5cfe0c43bdfde2699cca4" +
    "4bf86f6988f4087856c5022396c597b763b7f1fdf5d801e2bfb2d49b86f7d516c2661a8663674de5c44ecd4f6414d3ba" +
    "94bf48"

fun Context.getSignatureHash(): ByteArray {
    return OFFICIAL_SIGNATURE_HEX.hexToByteArray()
}