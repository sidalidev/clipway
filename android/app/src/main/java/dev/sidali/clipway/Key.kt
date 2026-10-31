package dev.sidali.clipway

import android.app.Activity
import android.content.Context
import android.graphics.Bitmap
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.Typeface
import android.graphics.pdf.PdfDocument
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.print.PrintManager
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPasswordOption
import androidx.credentials.PasswordCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.FileOutputStream
import java.text.DateFormat
import java.util.Date
import java.util.Locale

/** The 12-word key: reading what people type or scan, the password manager, the rescue kit. */
object Key {

    @Volatile
    private var list: List<String>? = null

    /** The official English BIP39 list (2048 words), bundled in res/raw. */
    fun wordList(c: Context): List<String> = list ?: c.resources.openRawResource(R.raw.bip39_english).bufferedReader()
        .readLines().map { it.trim() }.filter { it.isNotEmpty() }.also { list = it }

    fun words(c: Context, s: ByteArray): List<String> = Crypto.toWords(s, wordList(c))

    /** What a typed or scanned key gave. */
    sealed class Parsed {
        class Ok(val secret: ByteArray, val relay: String?) : Parsed()
        object NotTwelve : Parsed()
        object UnknownWord : Parsed()
        object BadChecksum : Parsed()
        object BadCode : Parsed()
        object RelayRefused : Parsed()
    }

    /** 12 words, or a clipway: code (pasted or scanned). Distinct errors, as the protocol asks. */
    fun parse(c: Context, text: String): Parsed {
        val t = text.trim()
        if (t.startsWith(Crypto.QR_PREFIX, ignoreCase = true)) {
            val p = try {
                Crypto.fromQr(t)
            } catch (e: IllegalArgumentException) {
                return Parsed.BadCode
            }
            if (p.relay != null && !Protocol.relayAllowed(p.relay, BuildConfig.ALLOW_LOCAL_HTTP)) return Parsed.RelayRefused
            return Parsed.Ok(p.secret, p.relay)
        }
        val words = t.lowercase(Locale.ROOT).split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (words.size != 12) return Parsed.NotTwelve
        val all = wordList(c)
        if (words.any { it !in all }) return Parsed.UnknownWord
        return try {
            Parsed.Ok(Crypto.fromWords(words.joinToString(" "), all), null)
        } catch (e: IllegalArgumentException) {
            Parsed.BadChecksum
        }
    }

    /** Credential Manager needs Android 14 here: older versions only reach it through Google services. */
    val passwordManagerAvailable: Boolean get() = Build.VERSION.SDK_INT >= 34

    enum class Saved { Yes, No, Cancelled }

    /** Hands the 12 words to the user's password manager (Proton Pass, Bitwarden...). */
    suspend fun save(activity: Activity, words: List<String>): Saved = try {
        CredentialManager.create(activity).createCredential(activity, CreatePasswordRequest(id = "Clipway", password = words.joinToString(" ")))
        Saved.Yes
    } catch (e: CreateCredentialCancellationException) {
        Saved.Cancelled
    } catch (e: Exception) {
        Saved.No
    }

    /** What the password manager gave: the saved words, nothing saved, or the user closed it. */
    sealed class Fetched {
        class Found(val text: String) : Fetched()
        object Nothing : Fetched()
        object Cancelled : Fetched()
    }

    suspend fun fromPasswordManager(activity: Activity): Fetched = try {
        val r = CredentialManager.create(activity).getCredential(activity, GetCredentialRequest(listOf(GetPasswordOption())))
        (r.credential as? PasswordCredential)?.password?.let { Fetched.Found(it) } ?: Fetched.Nothing
    } catch (e: NoCredentialException) {
        Fetched.Nothing
    } catch (e: Exception) {
        Fetched.Cancelled
    }

    /** A QR code as a bitmap (error correction M, as on the Mac), dark on light. */
    fun qr(text: String, size: Int, dark: Int, light: Int): Bitmap {
        val m = QRCodeWriter().encode(
            text, BarcodeFormat.QR_CODE, size, size,
            mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 1),
        )
        val px = IntArray(m.width * m.height) { i -> if (m.get(i % m.width, i / m.width)) dark else light }
        return Bitmap.createBitmap(px, m.width, m.height, Bitmap.Config.ARGB_8888)
    }

    // -----------------------------------------------------------------
    // Lock before showing the key: fingerprint, face or the phone's PIN
    // -----------------------------------------------------------------

    private const val AUTH = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL

    /** False on a phone without a screen lock: the screen then asks for a confirmation instead. */
    fun canLock(c: Context): Boolean =
        c.getSystemService(BiometricManager::class.java)?.canAuthenticate(AUTH) == BiometricManager.BIOMETRIC_SUCCESS

    fun unlock(activity: Activity, onOk: () -> Unit) {
        val prompt = BiometricPrompt.Builder(activity)
            .setTitle(activity.getString(R.string.key_unlock_title))
            .setSubtitle(activity.getString(R.string.key_unlock_body))
            .setAllowedAuthenticators(AUTH)
            .build()
        prompt.authenticate(CancellationSignal(), activity.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onOk()
        })
    }

    // -----------------------------------------------------------------
    // Rescue kit: two printable pages, through Android's print screen (which can save a PDF)
    // -----------------------------------------------------------------

    fun printKit(activity: Activity, words: List<String>, code: String, relayHost: String) {
        val pm = activity.getSystemService(PrintManager::class.java) ?: return
        val adapter = object : PrintDocumentAdapter() {
            override fun onLayout(
                old: PrintAttributes?, new: PrintAttributes, cancel: CancellationSignal?, cb: LayoutResultCallback, extras: Bundle?,
            ) {
                if (cancel?.isCanceled == true) return cb.onLayoutCancelled()
                cb.onLayoutFinished(
                    PrintDocumentInfo.Builder("clipway-rescue-kit.pdf").setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT).setPageCount(2).build(),
                    true,
                )
            }

            override fun onWrite(pages: Array<out PageRange>, dest: ParcelFileDescriptor, cancel: CancellationSignal?, cb: WriteResultCallback) {
                try {
                    val doc = kit(activity, words, code, relayHost)
                    FileOutputStream(dest.fileDescriptor).use { doc.writeTo(it) }
                    doc.close()
                    cb.onWriteFinished(arrayOf(PageRange.ALL_PAGES))
                } catch (e: Exception) {
                    cb.onWriteFailed(e.message)
                }
            }
        }
        pm.print(activity.getString(R.string.kit_job), adapter, PrintAttributes.Builder().setMediaSize(PrintAttributes.MediaSize.ISO_A4).build())
    }

    private fun kit(c: Context, words: List<String>, code: String, relayHost: String): PdfDocument {
        val doc = PdfDocument()
        val margin = 56f
        val width = 595f - 2 * margin
        val title = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 26f; typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD); color = Tokens.Print.ink }
        val head = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 15f; typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD); color = Tokens.Print.ink }
        val body = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 11.5f; color = Tokens.Print.ink }
        val gray = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 10.5f; color = Tokens.Print.gray }
        val word = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 17f; typeface = Typeface.MONOSPACE; color = Tokens.Print.ink }
        val num = Paint(Paint.ANTI_ALIAS_FLAG).apply { textSize = 12f; typeface = Typeface.MONOSPACE; color = Tokens.Print.gray }

        fun wrap(canvas: android.graphics.Canvas, text: String, paint: Paint, y0: Float): Float {
            var y = y0
            for (para in text.split("\n")) {
                var line = ""
                for (w in para.split(" ")) {
                    val tryLine = if (line.isEmpty()) w else "$line $w"
                    if (paint.measureText(tryLine) > width) {
                        canvas.drawText(line, margin, y, paint); y += paint.textSize * 1.45f; line = w
                    } else line = tryLine
                }
                if (line.isNotEmpty()) { canvas.drawText(line, margin, y, paint); y += paint.textSize * 1.45f }
                y += paint.textSize * 0.6f
            }
            return y
        }

        // Page 1: the key.
        val p1 = doc.startPage(PdfDocument.PageInfo.Builder(595, 842, 1).create())
        var cv = p1.canvas
        cv.drawText(c.getString(R.string.kit_title), margin, 84f, title)
        cv.drawText(DateFormat.getDateInstance(DateFormat.LONG, Locale.ENGLISH).format(Date()), margin, 106f, gray)
        cv.drawBitmap(qr(code, 600, Tokens.Print.ink, Tokens.Print.paper), null, Rect(56, 132, 256, 332), null)
        words.forEachIndexed { i, w ->
            val x = 292f + (i / 6) * 140f
            val y = 160f + (i % 6) * 32f
            cv.drawText("${i + 1}".padStart(2), x, y, num)
            cv.drawText(w, x + 26f, y, word)
        }
        var y = 380f
        y = wrap(cv, c.getString(R.string.kit_page1, relayHost), body, y)
        wrap(cv, c.getString(R.string.kit_warning), head, y + 8f)
        doc.finishPage(p1)

        // Page 2: for someone you trust.
        val p2 = doc.startPage(PdfDocument.PageInfo.Builder(595, 842, 2).create())
        cv = p2.canvas
        cv.drawText(c.getString(R.string.kit_trust_title), margin, 84f, title)
        wrap(cv, c.getString(R.string.kit_trust_body, relayHost), body, 124f)
        doc.finishPage(p2)
        return doc
    }
}
