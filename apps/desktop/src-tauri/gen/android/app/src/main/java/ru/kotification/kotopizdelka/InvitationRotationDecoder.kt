package ru.kotification.kotopizdelka

import com.google.zxing.BarcodeFormat
import com.google.zxing.DecodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.Reader
import com.google.zxing.Result
import com.google.zxing.ResultPoint
import com.journeyapps.barcodescanner.Decoder
import com.journeyapps.barcodescanner.DecoderFactory
import java.util.EnumMap

/** Retains JourneyApps' reader, binarizer and result-point callback. */
internal class InvitationDecoderFactory : DecoderFactory {
  override fun createDecoder(baseHints: MutableMap<DecodeHintType, *>): Decoder {
    val hints = EnumMap<DecodeHintType, Any?>(DecodeHintType::class.java)
    hints.putAll(baseHints)
    hints[DecodeHintType.POSSIBLE_FORMATS] = listOf(BarcodeFormat.QR_CODE)
    val reader = MultiFormatReader()
    reader.setHints(hints)
    return InvitationRotationDecoder(reader)
  }
}

/** Dense valid QRs can contain a false finder pattern that ends ZXing's search
 * early in one orientation. Retry only a failed frame, with at most three
 * quarter turns. Camera images stay in memory and are never saved or logged. */
internal class InvitationRotationDecoder(reader: Reader) : Decoder(reader) {
  private var turns = 0
  private var originalWidth = 0
  private var originalHeight = 0

  override fun decode(source: LuminanceSource): Result? {
    turns = 0
    originalWidth = source.width
    originalHeight = source.height
    super.decode(source)?.let { return it }

    val pixels = boundedPixels(originalWidth, originalHeight) ?: return null
    val matrix = try { source.matrix } catch (_: Exception) { return null }
    if (matrix.size < pixels) return null
    var current = MatrixSource(matrix, originalWidth, originalHeight)
    for (turn in 1..3) {
      current = current.clockwise()
      turns = turn
      val result = super.decode(current)
      if (result != null) {
        val points = result.resultPoints?.map { originalPoint(it) }?.toTypedArray()
        return Result(result.text, result.rawBytes, result.numBits, points,
          result.barcodeFormat, result.timestamp).also { mapped ->
          result.resultMetadata?.let { mapped.putAllMetadata(it) }
        }
      }
    }
    return null
  }

  override fun foundPossibleResultPoint(point: ResultPoint) {
    super.foundPossibleResultPoint(originalPoint(point))
  }

  private fun originalPoint(point: ResultPoint): ResultPoint = when (turns) {
    1 -> ResultPoint(point.y, originalHeight - point.x)
    2 -> ResultPoint(originalWidth - point.x, originalHeight - point.y)
    3 -> ResultPoint(originalWidth - point.y, point.x)
    else -> point
  }

  companion object {
    const val MAX_ROTATION_PIXELS = 4_000_000

    internal fun boundedPixels(width: Int, height: Int): Int? {
      if (width <= 0 || height <= 0) return null
      val pixels = width.toLong() * height.toLong()
      return if (pixels <= MAX_ROTATION_PIXELS) pixels.toInt() else null
    }
  }

  private class MatrixSource(private val bytes: ByteArray, width: Int, height: Int) : LuminanceSource(width, height) {
    override fun getRow(y: Int, row: ByteArray?): ByteArray {
      require(y >= 0 && y < height)
      val output = if (row != null && row.size >= width) row else ByteArray(width)
      bytes.copyInto(output, 0, y * width, (y + 1) * width)
      return output
    }

    override fun getMatrix(): ByteArray = bytes

    fun clockwise(): MatrixSource {
      val count = requireNotNull(boundedPixels(width, height))
      val rotated = ByteArray(count)
      for (y in 0 until height) {
        for (x in 0 until width) rotated[x * height + height - 1 - y] = bytes[y * width + x]
      }
      return MatrixSource(rotated, height, width)
    }
  }
}
