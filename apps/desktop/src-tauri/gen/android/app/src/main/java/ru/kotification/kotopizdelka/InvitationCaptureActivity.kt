package ru.kotification.kotopizdelka

import android.os.Bundle
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView

/** An unexported portrait activity, reachable only from our scanner command. */
class InvitationCaptureActivity : CaptureActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    // CaptureManager initializes the intent's decoder during super.onCreate.
    // Install the bounded fallback afterwards, before camera preview resumes.
    super.onCreate(savedInstanceState)
    findViewById<DecoratedBarcodeView>(com.google.zxing.client.android.R.id.zxing_barcode_scanner)
      .barcodeView.decoderFactory = InvitationDecoderFactory()
  }
}
