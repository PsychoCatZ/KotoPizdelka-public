package ru.kotification.kotopizdelka

import android.Manifest
import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.Permission
import app.tauri.annotation.PermissionCallback
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class NotificationSettingArgs { var enabled: Boolean = false }
@InvokeArg
class NotificationShowArgs { var viewed: Boolean = false }

/** Local notifications only. Rust reports committed new inbox progress. This
 * plugin never receives message text, names, routes, keys or invitation data. */
@TauriPlugin(permissions = [Permission(strings = [Manifest.permission.POST_NOTIFICATIONS], alias = "notifications")])
class LocalNotificationsPlugin(private val activity: Activity) : Plugin(activity) {
  private val preferences get() = Notifications.preferences(activity)
  private var requesting = false
  private fun permitted() = Notifications.permitted(activity)
  private fun allowed() = Notifications.allowed(activity)
  private fun createChannel() = Notifications.createChannel(activity)
  private fun reply(invoke: Invoke) {
    val result = JSObject()
    result.put("supported", true)
    result.put("enabled", preferences.getBoolean("enabled", false))
    result.put("allowed", allowed())
    invoke.resolve(result)
  }

  @Command
  fun settings(invoke: Invoke) { reply(invoke) }

  @Command
  fun configure(invoke: Invoke) {
    val args = invoke.parseArgs(NotificationSettingArgs::class.java)
    if (requesting) { invoke.reject("Запрос разрешения уже открыт."); return }
    if (!args.enabled) {
      preferences.edit().putBoolean("enabled", false).apply()
      Notifications.cancel(activity)
      reply(invoke)
      return
    }
    // The system permission dialog is reachable only from an explicit toggle.
    if (!permitted()) {
      requesting = true
      try { requestPermissionForAlias("notifications", invoke, "notificationPermissionResult") }
      catch (_: Exception) { requesting = false; invoke.reject("Не удалось запросить разрешение уведомлений.") }
      return
    }
    createChannel()
    preferences.edit().putBoolean("enabled", true).apply()
    reply(invoke)
  }

  @PermissionCallback
  fun notificationPermissionResult(invoke: Invoke) {
    requesting = false
    if (permitted()) { createChannel(); preferences.edit().putBoolean("enabled", true).apply() }
    else { preferences.edit().putBoolean("enabled", false).apply() }
    reply(invoke)
  }

  @Command
  fun show(invoke: Invoke) {
    val args = invoke.parseArgs(NotificationShowArgs::class.java)
    Notifications.show(activity.applicationContext, args.viewed && activity.hasWindowFocus())
    invoke.resolve()
  }
  private fun backgroundReply(invoke: Invoke) {
    val result = JSObject()
    result.put("supported", true)
    result.put("enabled", BackgroundSync.enabled(activity))
    result.put("interval_minutes", 15)
    invoke.resolve(result)
  }
  @Command
  fun backgroundSettings(invoke: Invoke) { backgroundReply(invoke) }
  @Command
  fun configureBackground(invoke: Invoke) {
    val args = invoke.parseArgs(NotificationSettingArgs::class.java)
    try { BackgroundSync.configure(activity.applicationContext, args.enabled); backgroundReply(invoke) }
    catch (_: Exception) { invoke.reject("Не удалось настроить фоновое получение. Откройте профиль и повторите.") }
  }
}
