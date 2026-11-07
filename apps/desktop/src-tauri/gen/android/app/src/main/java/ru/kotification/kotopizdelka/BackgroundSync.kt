package ru.kotification.kotopizdelka

import android.content.Context
import android.os.UserManager
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

object BackgroundSync {
  private const val WORK = "koto_private_periodic_sync_v1"
  fun preferences(context: Context) = context.getSharedPreferences("koto-background-sync", Context.MODE_PRIVATE)
  fun enabled(context: Context) = preferences(context).getBoolean("enabled", false)
  fun configure(context: Context, enabled: Boolean) {
    if (enabled && !BackgroundBridge.hasProfile()) throw IllegalStateException("Сначала создайте и откройте профиль.")
    // Commit consent before enqueue/cancel; a running job also checks this flag.
    if (!preferences(context).edit().putBoolean("enabled", enabled).commit()) throw IllegalStateException("Не удалось сохранить настройку.")
    reconcile(context)
    if (!enabled) BackgroundBridge.cancel()
  }
  fun reconcile(context: Context) {
    val manager = WorkManager.getInstance(context)
    if (!enabled(context)) { manager.cancelUniqueWork(WORK); return }
    val work = PeriodicWorkRequestBuilder<BackgroundSyncWorker>(15, TimeUnit.MINUTES)
      .setInitialDelay(1, TimeUnit.MINUTES)
      .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
      .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
      .build()
    // KEEP never resets the schedule on activity recreation or settings reads.
    manager.enqueueUniquePeriodicWork(WORK, ExistingPeriodicWorkPolicy.KEEP, work)
  }
}
class BackgroundSyncWorker(context: Context, parameters: WorkerParameters) : Worker(context, parameters) {
  override fun doWork(): Result {
    if (isStopped || !BackgroundSync.enabled(applicationContext)) return Result.success()
    if (!applicationContext.getSystemService(UserManager::class.java).isUserUnlocked) return Result.retry()
    return try {
      if (!BackgroundBridge.prepare(applicationContext)) return Result.retry()
      if (isStopped || !BackgroundSync.enabled(applicationContext) || !BackgroundBridge.hasProfile()) return Result.success()
      BackgroundBridge.begin()
      if (isStopped || !BackgroundSync.enabled(applicationContext)) return Result.success()
      val prefs = BackgroundSync.preferences(applicationContext)
      val result = BackgroundBridge.sync(prefs.getInt("cursor", 0))
      if (result == 2L) return Result.success() // no profile / activity already visible
      if (isStopped || !BackgroundSync.enabled(applicationContext)) return Result.success()
      prefs.edit().putInt("cursor", (result ushr 2).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()).apply()
      if ((result and 1L) != 0L && !isStopped && BackgroundSync.enabled(applicationContext)) Result.retry() else Result.success()
    } catch (_: Exception) { Result.retry() }
  }
  override fun onStopped() {
    // Only bounded network operations may finish; never start another pass.
    try { BackgroundBridge.cancel() } catch (_: Exception) { }
    super.onStopped()
  }
}
