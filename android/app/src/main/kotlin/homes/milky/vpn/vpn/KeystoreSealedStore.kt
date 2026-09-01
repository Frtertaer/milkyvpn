package homes.milky.vpn.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Small Android-Keystore-backed sealed storage used by the VPN service for the
 * "last good profile" needed by Always-on VPN / system restarts, when Flutter is not running.
 *
 * - AES-256-GCM key lives in AndroidKeyStore (non-exportable).
 * - Ciphertext is written to a private file in `noBackupFilesDir`
 *   (also excluded from backup by the manifest rules).
 * - The Flutter side uses flutter_secure_storage for the subscription token; this store only
 *   holds the single profile spec required to bring the tunnel up autonomously.
 */
class KeystoreSealedStore(private val context: Context, private val name: String) {

    private val keyAlias = "milkyvpn_sealed_$name"
    private val file: File get() = File(context.noBackupFilesDir, "$name.sealed")

    fun write(plaintext: String) {
        val key = getOrCreateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val out = ByteArray(1 + iv.size + ct.size)
        out[0] = iv.size.toByte()
        System.arraycopy(iv, 0, out, 1, iv.size)
        System.arraycopy(ct, 0, out, 1 + iv.size, ct.size)
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(out)
        if (!tmp.renameTo(file)) {
            file.writeBytes(out)
            tmp.delete()
        }
    }

    fun read(): String? {
        if (!file.exists()) return null
        return try {
            val data = file.readBytes()
            val ivLen = data[0].toInt()
            val iv = data.copyOfRange(1, 1 + ivLen)
            val ct = data.copyOfRange(1 + ivLen, data.size)
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = ks.getKey(keyAlias, null) as? SecretKey ?: return null
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            String(cipher.doFinal(ct), Charsets.UTF_8)
        } catch (t: Throwable) {
            SafeLog.w("sealed store unreadable, clearing", t)
            clear()
            null
        }
    }

    fun clear() {
        file.delete()
    }

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(keyAlias, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return gen.generateKey()
    }
}
