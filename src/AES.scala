import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

import scala.annotation.tailrec
import scala.util.Random

object Enc extends Enumeration {
  val Encrypt, Decrypt = Value
}

object EncMethod extends Enumeration {
  val ECB, CBC = Value
}

object AES {
  def randomBytes(len: Int): Seq[Byte] = {
    val data = new Array[Byte](len)
    Random.nextBytes(data)
    data
  }

  @tailrec
  def randomString(len: Int, acc: String = ""): String = {
    if(len == 0)
      acc
    else
      randomString(len-1, Random.nextPrintableChar() +: acc)
  }

  def getAESCipher(key: String, encrypt: Enc.Value): Cipher = {
    val c = Cipher.getInstance("AES/ECB/NoPadding")
    c.init(if(encrypt == Enc.Encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, new SecretKeySpec(key.getBytes, "AES"))
    c
  }

  def processECB(enc: Enc.Value, data: Seq[Byte], key: String) =
    getAESCipher(key, enc).doFinal(data.toArray)

  def encrypt(data: Seq[Byte], key: String): Seq[Byte] =
    processECB(Enc.Encrypt, data, key)

  def decrypt(data: Seq[Byte], key: String): Seq[Byte] =
    processECB(Enc.Decrypt, data, key)

  def isECB(data: Seq[Byte]): Boolean =
    data.sliding(16, 16).toSeq.distinct.length < (data.length + 15) / 16

  def padPKCS7(data: Seq[Byte], size: Int = 16): Seq[Byte] = {
    val padlen = (data.length / size + 1) * size - data.length
    data.padTo(data.length + padlen, padlen.toByte)
  }

  def padPKCS7(data: String, size: Int): String =
    Utils.binaryToString(padPKCS7(Utils.stringToBinary(data), size))

  def unpadPKCS7(data: Seq[Byte], size: Int = 16): Option[Seq[Byte]] = {
    val padlen = data.last
    if(!(1 to size).contains(padlen) || data.length < padlen)
      None
    else {
      val (unpadded, padding) = data.splitAt(data.length - padlen)
      if(padding.length != padlen || padding.exists(_ != padlen) || data.length % size != 0)
        None
      else
        Some(unpadded)
    }
  }

  def unpadPKCS7(data: String, size: Int): Option[String] =
    unpadPKCS7(Utils.stringToBinary(data), size).map(Utils.binaryToString)

  def processCBC(enc: Enc.Value, data: Seq[Byte], key: String, iv: Option[Seq[Byte]]): Seq[Byte] = {
    val c = getAESCipher(key, enc)

    @tailrec
    def processCBCBlock(data: Seq[Byte], v: IndexedSeq[Byte], acc: Seq[Byte]): Seq[Byte] = {
      if(data.isEmpty)
        acc
      else {
        val (blk, rest) = data.splitAt(16)
        val dec =
          if(enc == Enc.Encrypt)
            c.doFinal(XOR.xor(blk, v).toArray).toSeq
          else
            XOR.xor(c.doFinal(blk.toArray).toSeq, v)
        processCBCBlock(rest, blk.toIndexedSeq, acc ++ dec)
      }
    }

    processCBCBlock(data, iv.getOrElse(Seq.fill(16)(0.toByte)).toIndexedSeq, Seq())
  }

  def encryptCBC(data: Seq[Byte], key: String, iv: Option[Seq[Byte]] = None): Seq[Byte] =
    processCBC(Enc.Encrypt, data, key, iv)

  def decryptCBC(data: Seq[Byte], key: String, iv: Option[Seq[Byte]] = None): Seq[Byte] =
    processCBC(Enc.Decrypt, data, key, iv)

  case class OracleOutput(data: Seq[Byte], method: EncMethod.Value, key: String, prepend: Seq[Byte], append: Seq[Byte], iv: Seq[Byte])

  def encOracle(data: Seq[Byte]): OracleOutput = {
    val key = randomString(16)
    val prepend = randomBytes(Random.nextInt(6) + 5)
    val append = randomBytes(Random.nextInt(6) + 5)
    val iv = randomBytes(16)
    val method = if(Random.nextBoolean) EncMethod.ECB else EncMethod.CBC
    val decrypted = padPKCS7(prepend ++ data ++ append, 16)
    val encrypted =
      if(method == EncMethod.ECB)
        encrypt(padPKCS7(decrypted), key)
      else
        encryptCBC(decrypted, key, Some(iv))
    OracleOutput(encrypted, method, key, prepend, append, iv)
  }

  def decOracle(data: Seq[Byte]): EncMethod.Value = {
    if(data.slice(16, 16*2) == data.slice(16*2, 16*3))
      EncMethod.ECB
    else
      EncMethod.CBC
  }

  def checkOracle: Boolean = {
    val text = Utils.stringToBinary("z" + "a" * (16 * 3))
    val o = encOracle(text)
    decOracle(o.data) == o.method
  }
}
