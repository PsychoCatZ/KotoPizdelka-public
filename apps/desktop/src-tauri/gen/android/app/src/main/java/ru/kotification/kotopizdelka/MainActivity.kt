package ru.kotification.kotopizdelka

import android.os.Bundle
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : TauriActivity() {
  private var started = false
  override fun onStart() { super.onStart(); started = true; BackgroundBridge.presentation(true, hasWindowFocus()) }
  override fun onStop() { started = false; BackgroundBridge.presentation(false, false); super.onStop() }
  override fun onWindowFocusChanged(focus: Boolean) { super.onWindowFocusChanged(focus); BackgroundBridge.presentation(started, focus) }
  override fun onCreate(savedInstanceState: Bundle?) {
    check(BackgroundBridge.prepare(applicationContext)) { "Android runtime не готов." }
    BackgroundSync.reconcile(applicationContext)
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    // Keep the WebView inside the system bars, cutout and keyboard even when
    // Android enforces edge-to-edge for recent target SDKs.
    val content = findViewById<View>(android.R.id.content)
    content.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val edges = insets.getInsets(
        WindowInsetsCompat.Type.systemBars() or
          WindowInsetsCompat.Type.displayCutout() or WindowInsetsCompat.Type.ime()
      )
      view.setPadding(edges.left, edges.top, edges.right, edges.bottom)
      WindowInsetsCompat.CONSUMED
    }
    ViewCompat.requestApplyInsets(content)
  }
}
