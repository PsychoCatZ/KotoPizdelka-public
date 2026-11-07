package ru.kotification.kotopizdelka

import android.app.Activity
import android.content.Intent
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File
import java.util.UUID

@InvokeArg
class BackupExportArgs { lateinit var path: String }

/** User-selected SAF documents; only opaque encrypted archives enter the cache. */
@TauriPlugin
class ProfileBackupPlugin(private val activity: Activity) : Plugin(activity) {
  @Volatile private var busy = false
  private var exporting: File? = null
  private val maximum = 128L * 1024 * 1024
  private fun folder(): File = File(activity.cacheDir, "profile-backups").apply { mkdirs() }
  private fun exportFile(path: String): File {
    val file = File(path).canonicalFile
    require(file.parentFile == folder().canonicalFile)
    require(file.name.matches(Regex("export-[0-9]+\\.kotobackup")))
    require(file.isFile && file.length() in 1..maximum)
    return file
  }
  @Command
  @Synchronized
  fun save(invoke: Invoke) {
    if (busy) { invoke.reject("Выбор файла уже открыт."); return }
    try {
      exporting = exportFile(invoke.parseArgs(BackupExportArgs::class.java).path)
      busy = true
      val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
        addCategory(Intent.CATEGORY_OPENABLE)
        type = "application/octet-stream"
        putExtra(Intent.EXTRA_TITLE, "KotoPizdelka-profile-${System.currentTimeMillis()}.kotobackup")
      }
      startActivityForResult(invoke, intent, "saved")
    } catch (_: Exception) { busy = false; exporting = null; invoke.reject("Не удалось открыть сохранение копии.") }
  }
  @ActivityCallback
  fun saved(invoke: Invoke, result: ActivityResult) {
    val source = exporting
    exporting = null
    if (result.resultCode != Activity.RESULT_OK || result.data?.data == null) {
      busy = false; invoke.resolve(JSObject().apply { put("done", false) }); return
    }
    val uri = result.data!!.data!!
    Thread {
      try {
        require(uri.scheme == "content" && !uri.authority.orEmpty().startsWith(activity.packageName))
        require(source != null)
        exportFile(source.path).inputStream().use { input ->
          activity.contentResolver.openOutputStream(uri, "wt")!!.use { output ->
            input.copyTo(output); output.flush()
          }
        }
        invoke.resolve(JSObject().apply { put("done", true) })
      } catch (_: Exception) { invoke.reject("Не удалось сохранить копию. Проверь место и выбранное хранилище.") }
      finally { busy = false }
    }.start()
  }
  @Command
  @Synchronized
  fun open(invoke: Invoke) {
    if (busy) { invoke.reject("Выбор файла уже открыт."); return }
    busy = true
    try {
      val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
        addCategory(Intent.CATEGORY_OPENABLE)
        type = "*/*"
      }
      startActivityForResult(invoke, intent, "opened")
    } catch (_: Exception) { busy = false; invoke.reject("Не удалось открыть выбор копии.") }
  }
  @ActivityCallback
  fun opened(invoke: Invoke, result: ActivityResult) {
    if (result.resultCode != Activity.RESULT_OK || result.data?.data == null) {
      busy = false; invoke.resolve(JSObject().apply { put("path", org.json.JSONObject.NULL) }); return
    }
    val uri = result.data!!.data!!
    Thread {
      val target = File(folder(), "import-${UUID.randomUUID()}.kotobackup")
      try {
        require(uri.scheme == "content" && !uri.authority.orEmpty().startsWith(activity.packageName))
        activity.contentResolver.openInputStream(uri)!!.use { input ->
          target.outputStream().use { output ->
            val buffer = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
              val count = input.read(buffer)
              if (count < 0) break
              total += count
              require(total <= maximum)
              output.write(buffer, 0, count)
            }
            require(total > 0)
          }
        }
        invoke.resolve(JSObject().apply { put("path", target.canonicalPath) })
      } catch (_: Exception) { target.delete(); invoke.reject("Файл копии не прочитан или слишком большой.") }
      finally { busy = false }
    }.start()
  }
}
