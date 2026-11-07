package ru.kotification.kotopizdelka

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.Reader
import com.google.zxing.Result
import com.google.zxing.ResultMetadataType
import com.google.zxing.ResultPoint
import com.journeyapps.barcodescanner.Decoder
import org.junit.Assert.*
import org.junit.Test

class InvitationRotationDecoderTest {
  /** Locally generated dummy invitation. Its interior contains a pattern that
   * prematurely stops ZXing 3.4.1's finder search at this scale. */
  @Test fun validDenseQrRecoversFromTheRealFinderFailure() {
    val rows = resource("invitation-false-finder-matrix.txt").trim().lines()
    val scale = 5
    val size = rows.size * scale
    val pixels = ByteArray(size * size) { index ->
      if (rows[index / size / scale][index % size / scale] == '#') 0 else 255.toByte()
    }
    val source = TestSource(size, size, pixels)
    val reader = MultiFormatReader().apply {
      setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }
    assertNull("This fixture must exercise a failed normal scan", Decoder(reader).decode(source))
    val decoder = InvitationDecoderFactory().createDecoder(mutableMapOf<DecodeHintType, Any>())
    val decoded = requireNotNull(decoder.decode(source))
    assertEquals(resource("invitation-false-finder-link.txt").trim(), decoded.text)
    assertEquals(BarcodeFormat.QR_CODE, decoded.barcodeFormat)
    // Return finder/alignment coordinates in the original camera frame.
    assertTrue(decoded.resultPoints.any { close(it.x, 37.5f) && close(it.y, 37.5f) })
    assertTrue(decoded.resultPoints.any { close(it.x, 587.5f) && close(it.y, 37.5f) })
    assertTrue(decoded.resultPoints.any { close(it.x, 37.5f) && close(it.y, 587.5f) })
  }

  @Test fun successReturnsEarlyAndMapsResultAndPreviewPoints() {
    val expected = listOf(
      ResultPoint(1.5f, 1.25f), ResultPoint(1.25f, 1.5f),
      ResultPoint(2.5f, 1.75f), ResultPoint(2.75f, 1.5f)
    )
    for (success in 1..4) {
      val reader = ScriptedReader(success)
      val decoder = InvitationRotationDecoder(reader)
      reader.pointCallback = decoder::foundPossibleResultPoint
      val source = TestSource(4, 3, ByteArray(12) { it.toByte() })
      val result = requireNotNull(decoder.decode(source))
      assertEquals(success, reader.attempts)
      assertEquals(if (success == 1) 0 else 1, source.matrixReads)
      assertEquals(listOf(4 to 3, 3 to 4, 4 to 3, 3 to 4).take(success), reader.sizes)
      assertEquals("sentinel", result.text)
      assertArrayEquals(byteArrayOf(1, 2), result.rawBytes)
      assertEquals(16, result.numBits)
      assertEquals(42L, result.timestamp)
      assertEquals("M", result.resultMetadata[ResultMetadataType.ERROR_CORRECTION_LEVEL])
      assertPoint(expected[success - 1], result.resultPoints.single())
      assertPoint(expected[success - 1], decoder.possibleResultPoints.single())
    }
  }

  @Test fun aFailedFrameStopsAfterFourAttempts() {
    val reader = ScriptedReader(Int.MAX_VALUE)
    val source = TestSource(4, 3, ByteArray(12))
    assertNull(InvitationRotationDecoder(reader).decode(source))
    assertEquals(4, reader.attempts)
    assertEquals(1, source.matrixReads)
  }

  @Test fun oversizedOrOverflowingFramesDoNotAllocateRotationMatrices() {
    assertEquals(4_000_000, InvitationRotationDecoder.boundedPixels(2000, 2000))
    for ((width, height) in listOf(2001 to 2000, Int.MAX_VALUE to Int.MAX_VALUE,
        0 to 10, 10 to 0, -1 to 10)) {
      assertNull(InvitationRotationDecoder.boundedPixels(width, height))
    }
    val reader = ScriptedReader(Int.MAX_VALUE)
    val source = TestSource(Int.MAX_VALUE, Int.MAX_VALUE, byteArrayOf())
    assertNull(InvitationRotationDecoder(reader).decode(source))
    assertEquals(1, reader.attempts)
    assertEquals(0, source.matrixReads)
  }

  @Test fun aTruncatedMatrixStopsBeforeRotation() {
    val reader = ScriptedReader(Int.MAX_VALUE)
    val source = TestSource(4, 3, ByteArray(11))
    assertNull(InvitationRotationDecoder(reader).decode(source))
    assertEquals(1, reader.attempts)
  }

  private fun close(a: Float, b: Float) = kotlin.math.abs(a - b) < 0.01f
  private fun assertPoint(expected: ResultPoint, actual: ResultPoint) {
    assertEquals(expected.x, actual.x, 0.01f)
    assertEquals(expected.y, actual.y, 0.01f)
  }
  private fun resource(name: String): String = requireNotNull(javaClass.classLoader.getResourceAsStream(name))
    .bufferedReader(Charsets.US_ASCII).use { it.readText() }

  private class TestSource(width: Int, height: Int, private val bytes: ByteArray) : LuminanceSource(width, height) {
    var matrixReads = 0
    override fun getMatrix(): ByteArray { matrixReads++; return bytes }
    override fun getRow(y: Int, row: ByteArray?): ByteArray = bytes.copyOfRange(y * width, (y + 1) * width)
  }

  private class ScriptedReader(private val successAttempt: Int) : Reader {
    var attempts = 0
    val sizes = mutableListOf<Pair<Int, Int>>()
    var pointCallback: ((ResultPoint) -> Unit)? = null
    override fun decode(bitmap: BinaryBitmap): Result {
      attempts++
      sizes.add(bitmap.width to bitmap.height)
      pointCallback?.invoke(ResultPoint(1.5f, 1.25f))
      if (attempts != successAttempt) throw NotFoundException.getNotFoundInstance()
      return Result("sentinel", byteArrayOf(1, 2), 16,
        arrayOf(ResultPoint(1.5f, 1.25f)), BarcodeFormat.QR_CODE, 42L).also {
        it.putMetadata(ResultMetadataType.ERROR_CORRECTION_LEVEL, "M")
      }
    }
    override fun decode(bitmap: BinaryBitmap, hints: MutableMap<DecodeHintType, *>?): Result = decode(bitmap)
    override fun reset() {}
  }
}
