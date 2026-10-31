package dev.sidali.clipway

import android.annotation.SuppressLint
import android.content.Context
import android.content.res.Configuration
import android.graphics.ImageFormat
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.util.Log
import android.util.Size
import android.view.Surface
import android.view.TextureView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executor

/**
 * QR code reader without a scanning library: Camera2 preview in a TextureView, YUV frames read by
 * ZXing core (also used to draw codes). The CAMERA permission must be granted before showing it.
 * [onText] is called once, on the main thread, with the first code read.
 */
@Composable
fun QrScanner(onText: (String) -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val camera = remember { QrCamera(context, onText) }
    val size = remember { camera.size }
    // In portrait the sensor image is turned a quarter: keep its proportions.
    val portrait = LocalConfiguration.current.orientation != Configuration.ORIENTATION_LANDSCAPE
    val ratio = if (portrait) size.height.toFloat() / size.width else size.width.toFloat() / size.height
    DisposableEffect(Unit) {
        onDispose { camera.close() }
    }
    Box(modifier) {
        AndroidView(
            factory = { ctx -> TextureView(ctx).also { camera.attach(it) } },
            modifier = Modifier
                .fillMaxWidth()
                .aspectRatio(ratio),
        )
    }
}

/** Back camera, preview and analysis. Everything about the camera runs on its own thread. */
@SuppressLint("MissingPermission") // CAMERA checked by the screen before showing the reader
private class QrCamera(context: Context, private val onText: (String) -> Unit) {

    private val app = context.applicationContext ?: context
    private val manager = app.getSystemService(CameraManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private val thread = HandlerThread("clipway-qr").apply { start() }
    private val background = Handler(thread.looper)
    private val executor = Executor { background.post(it) }
    private val reader = QRCodeReader()
    private val hints = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))

    private val cameraId: String? = try {
        manager.cameraIdList.firstOrNull {
            manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
        } ?: manager.cameraIdList.firstOrNull()
    } catch (e: Exception) {
        null
    }

    /** Size shared by the preview and the analysis: the largest up to 1280 x 960. */
    val size: Size = chooseSize()

    @Volatile
    private var closed = false

    @Volatile
    private var read = false
    private var device: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var images: ImageReader? = null
    private var previewSurface: Surface? = null

    private fun chooseSize(): Size {
        val fallback = Size(640, 480)
        val id = cameraId ?: return fallback
        return try {
            val map = manager.getCameraCharacteristics(id)
                .get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: return fallback
            val preview = map.getOutputSizes(SurfaceTexture::class.java)?.toSet() ?: emptySet()
            map.getOutputSizes(ImageFormat.YUV_420_888)
                ?.filter { it in preview && it.width <= 1280 && it.height <= 960 }
                ?.maxByOrNull { it.width * it.height } ?: fallback
        } catch (e: Exception) {
            fallback
        }
    }

    fun attach(view: TextureView) {
        view.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(st: SurfaceTexture, l: Int, h: Int) {
                st.setDefaultBufferSize(size.width, size.height)
                val surface = Surface(st)
                background.post { open(surface) }
            }

            override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, l: Int, h: Int) = Unit

            override fun onSurfaceTextureDestroyed(st: SurfaceTexture): Boolean {
                close()
                return true
            }

            override fun onSurfaceTextureUpdated(st: SurfaceTexture) = Unit
        }
    }

    private fun open(surface: Surface) {
        val id = cameraId ?: return
        if (closed) return
        previewSurface = surface
        val imageReader = ImageReader.newInstance(size.width, size.height, ImageFormat.YUV_420_888, 2)
        imageReader.setOnImageAvailableListener({ analysis(it) }, background)
        images = imageReader
        try {
            manager.openCamera(id, executor, object : CameraDevice.StateCallback() {
                override fun onOpened(camera: CameraDevice) {
                    if (closed) {
                        camera.close()
                        return
                    }
                    device = camera
                    startSession(camera, surface, imageReader.surface)
                }

                override fun onDisconnected(camera: CameraDevice) = camera.close()

                override fun onError(camera: CameraDevice, error: Int) {
                    Log.w(TAG, "Camera error ($error)")
                    camera.close()
                }
            })
        } catch (e: Exception) {
            Log.w(TAG, "Cannot open the camera: ${e.message}")
        }
    }

    private fun startSession(camera: CameraDevice, preview: Surface, analysis: Surface) {
        val outputs = listOf(OutputConfiguration(preview), OutputConfiguration(analysis))
        val config = SessionConfiguration(
            SessionConfiguration.SESSION_REGULAR,
            outputs,
            executor,
            object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(s: CameraCaptureSession) {
                    if (closed) {
                        s.close()
                        return
                    }
                    session = s
                    try {
                        val request = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                            addTarget(preview)
                            addTarget(analysis)
                            set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                        }
                        s.setRepeatingRequest(request.build(), null, background)
                    } catch (e: Exception) {
                        Log.w(TAG, "Cannot start the preview: ${e.message}")
                    }
                }

                override fun onConfigureFailed(s: CameraCaptureSession) {
                    Log.w(TAG, "Camera session refused")
                }
            },
        )
        try {
            camera.createCaptureSession(config)
        } catch (e: Exception) {
            Log.w(TAG, "Cannot open a camera session: ${e.message}")
        }
    }

    /** Reads the luminance (Y plane) of the latest frame; late frames are skipped. */
    private fun analysis(source: ImageReader) {
        val image = try {
            source.acquireLatestImage()
        } catch (e: Exception) {
            null
        } ?: return
        try {
            if (read || closed) return
            val plane = image.planes[0]
            val stride = plane.rowStride
            val l = image.width
            val h = image.height
            val buffer = plane.buffer
            val bytes = ByteArray(stride * h)
            buffer.get(bytes, 0, minOf(buffer.remaining(), bytes.size))
            val luminance = PlanarYUVLuminanceSource(bytes, stride, h, 0, 0, l, h, false)
            val text = try {
                reader.decode(BinaryBitmap(HybridBinarizer(luminance)), hints).text
            } catch (e: ReaderException) {
                null
            } finally {
                reader.reset()
            }
            if (text != null && !read) {
                read = true
                main.post { if (!closed) onText(text) }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Cannot decode the frame: ${e.message}")
        } finally {
            image.close()
        }
    }

    fun close() {
        if (closed) return
        closed = true
        background.post {
            try {
                session?.close()
                device?.close()
                images?.close()
                previewSurface?.release()
            } catch (_: Exception) {
            }
            session = null
            device = null
            images = null
            previewSurface = null
            thread.quitSafely()
        }
    }

    private companion object {
        const val TAG = "ClipwayQr"
    }
}
