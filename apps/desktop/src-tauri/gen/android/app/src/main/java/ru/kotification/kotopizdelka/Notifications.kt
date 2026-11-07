package ru.kotification.kotopizdelka

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

object Notifications {
  private const val CHANNEL = "koto_messages_private_v1"
  private const val NOTIFICATION_ID = 17101
  fun preferences(context: Context) = context.getSharedPreferences("koto-local-notifications", Context.MODE_PRIVATE)
  fun manager(context: Context) = context.getSystemService(NotificationManager::class.java)
  fun permitted(context: Context): Boolean = Build.VERSION.SDK_INT < 33 || context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
  fun allowed(context: Context): Boolean = permitted(context) && manager(context).areNotificationsEnabled() && manager(context).getNotificationChannel(CHANNEL)?.importance != NotificationManager.IMPORTANCE_NONE
  fun createChannel(context: Context) {
    val channel = NotificationChannel(CHANNEL, "Личные сообщения", NotificationManager.IMPORTANCE_DEFAULT)
    channel.description = "Новые сообщения без имени собеседника и текста переписки"
    channel.enableVibration(false)
    channel.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
    manager(context).createNotificationChannel(channel)
  }
  fun cancel(context: Context) { manager(context).cancel(NOTIFICATION_ID) }
  fun show(context: Context, viewed: Boolean) {
    if (viewed || !preferences(context).getBoolean("enabled", false) || !allowed(context)) return
    try {
      createChannel(context)
      val launch = Intent(context, MainActivity::class.java)
        .setAction(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        .setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
      val pending = PendingIntent.getActivity(context, 0, launch, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
      val notification = Notification.Builder(context, CHANNEL)
        .setSmallIcon(R.drawable.ic_stat_cat).setContentTitle("КотоПизделка")
        .setContentText("Новое сообщение в КотоПизделке").setContentIntent(pending)
        .setVisibility(Notification.VISIBILITY_PRIVATE).setCategory(Notification.CATEGORY_MESSAGE)
        .setAutoCancel(true).setOnlyAlertOnce(true).build()
      manager(context).notify(NOTIFICATION_ID, notification)
    } catch (_: Exception) { /* Never block delivery on notification failure. */ }
  }
}
