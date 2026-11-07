package ru.kotification.kotopizdelka

import android.app.Activity
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/** An explicit user action launches an offline camera scanner. No image leaves
 * this activity, no gallery copy is written, and no Google Play service is used.
 * Camera permission is requested by CaptureActivity only after launching it. */
@TauriPlugin
class InvitationScannerPlugin(private val activity: Activity) : Plugin(activity) {
  private var scanning = false

  @Command
  fun scan(invoke: Invoke) {
    if (scanning) {
      invoke.reject("Сканирование уже открыто.")
      return
    }
    val options = ScanOptions()
      .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
      .setCaptureActivity(InvitationCaptureActivity::class.java)
      .setPrompt("Наведите камеру на приглашение КотоПизделки")
      .setBeepEnabled(false)
      .setBarcodeImageEnabled(false)
      .setOrientationLocked(false)
      .setTimeout(120_000L)
    scanning = true
    try {
      startActivityForResult(invoke, options.createScanIntent(activity), "scanResult")
    } catch (_: Exception) {
      scanning = false
      invoke.reject("Не удалось открыть камеру.")
    }
  }

  @ActivityCallback
  fun scanResult(invoke: Invoke, result: ActivityResult) {
    scanning = false
    val contents = ScanContract().parseResult(result.resultCode, result.data).contents
    val reply = JSObject()
    if (contents == null) {
      reply.put("link", org.json.JSONObject.NULL)
    } else if (contents.length <= 2300 &&
      contents.startsWith("kotopizdelka://invite#") &&
      contents.removePrefix("kotopizdelka://invite#").isNotEmpty() &&
      contents.removePrefix("kotopizdelka://invite#").all {
        it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_'
      }) {
      reply.put("link", contents)
    } else {
      invoke.reject("Это не QR-код приглашения КотоПизделки.")
      return
    }
    invoke.resolve(reply)
  }
}
