package ru.kotification.kotopizdelka

import android.content.Context

/** JNI has no path/capability/text arguments; context supplies the fixed private path. */
object BackgroundBridge {
  init { System.loadLibrary("kotopizdelka_lib") }
  @Volatile private var application: Context? = null
  fun prepare(context: Context): Boolean {
    application = context.applicationContext
    return initialize(context.applicationContext)
  }
  @JvmStatic external fun initialize(context: Context): Boolean
  @JvmStatic external fun hasProfile(): Boolean
  @JvmStatic external fun presentation(started: Boolean, focused: Boolean)
  @JvmStatic external fun sync(cursor: Int): Long
  @JvmStatic external fun begin()
  @JvmStatic external fun cancel()
  @JvmStatic fun backgroundEnabled(): Boolean = application?.let { BackgroundSync.enabled(it) } ?: false
  @JvmStatic fun notifyIncoming(viewed: Boolean) {
    application?.let { Notifications.show(it, viewed) }
  }
}
