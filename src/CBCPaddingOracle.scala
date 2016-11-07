import scala.annotation.tailrec
import scala.util.Random

object CBCPaddingOracle {
  type Decryptor = (Seq[Byte], Seq[Byte]) => Boolean

  def validContent(content: Seq[Byte], key: String, iv: Seq[Byte]): Boolean =
    AES.unpadPKCS7(AES.decryptCBC(content, key, Some(iv))).isDefined

  def cbcPaddingOracle(data: Seq[Byte], decryptor: Decryptor): Option[String] = {
    def xorDecryptor(data: Seq[Byte], xor: Seq[Byte]): Boolean = {
      val (iv, xorVal) = (IndexedSeq.fill[Byte](data.length - xor.length)(0) ++ xor ++ Seq.fill[Byte](16)(0)).splitAt(16)
      decryptor(XOR.xor(data, xorVal), iv)
    }

    @tailrec
    def findPaddingLength(acc: Int = 0): Int =
      if(xorDecryptor(data, 1.toByte +: Seq.fill[Byte](acc)(0)))
        acc
      else
        findPaddingLength(acc + 1)

    val paddingLength = findPaddingLength()

    def decryptXorByte(xorByte: Byte, known: Seq[Byte], cutRight: Int): Boolean =
      xorDecryptor(data.dropRight(cutRight), (xorByte +: XOR.xor(known, (known.length - cutRight + 1).toByte)).dropRight(cutRight))

    @tailrec
    def cbcPaddingOracleInner(known: Seq[Byte], index: Int): Seq[Byte] = {
      if(index == -1)
        known
      else {
        val cutRight = known.length / 16 * 16
        @tailrec
        def decryptByte(b: Byte = Byte.MinValue): Byte =
          if(decryptXorByte(b, known, cutRight))
            (b ^ (known.length - cutRight + 1)).toByte
          else
            decryptByte((b + 1).toByte)

        cbcPaddingOracleInner(decryptByte() +: known, index - 1)
      }
    }

    val dec = cbcPaddingOracleInner(Seq.fill(paddingLength)(paddingLength.toByte), data.length - paddingLength - 1)
    AES.unpadPKCS7(Utils.binaryToString(dec), 16)
  }
}
