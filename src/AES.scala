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
    if(data.length < padlen || padlen == 0 /* || !(1 to size).contains(padlen)*/)
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
        val nextVec = if(enc == Enc.Encrypt) dec else blk
        processCBCBlock(rest, nextVec.toIndexedSeq, acc ++ dec)
      }
    }

    processCBCBlock(data, iv.getOrElse(Seq.fill(16)(0.toByte)).toIndexedSeq, Seq())
  }

  def encryptCBC(data: Seq[Byte], key: String, iv: Option[Seq[Byte]] = None): Seq[Byte] =
    processCBC(Enc.Encrypt, data, key, iv)

  def decryptCBC(data: Seq[Byte], key: String, iv: Option[Seq[Byte]] = None): Seq[Byte] =
    processCBC(Enc.Decrypt, data, key, iv)

  def keyStreamBlock(c: Cipher, nonce: Array[Byte], counter: Long): Seq[Byte] = {
    val counterBytes = Seq.tabulate(8)(x => ((counter >> (x << 1)) & 0xFF).toByte)
    c.doFinal(nonce ++ counterBytes)
  }

  type KeyStream = Stream[Byte]

  def genKeyStream(key: String, nonce: Array[Byte] = Array.fill(8)(0), counter: Long = 0): KeyStream = {
    val c = getAESCipher(key, Enc.Encrypt)

    def loop(counter: Long): KeyStream =
      keyStreamBlock(c, nonce, counter).toStream #::: loop(counter + 1)
    loop(counter)
  }

  def encryptCTR(data: Seq[Byte], keyStream: KeyStream): Seq[Byte] =
    XOR.xorStream(data, keyStream)

  def decryptCTR(data: Seq[Byte], keyStream: KeyStream): Seq[Byte] =
    encryptCTR(data, keyStream)

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

  val checkOracleText = Utils.stringToBinary("z" + "a" * (16 * 3))

  def checkOracle: Boolean = {
    val o = encOracle(checkOracleText)
    decOracle(o.data) == o.method
  }

  type Encryptor = Seq[Byte] => Seq[Byte]

  // (block size, textLen)
  def findBlockSize(encryptor: Encryptor): (Int, Int) = {
    val startSize = encryptor(Seq()).length
    @tailrec
    def findBlockSizeInner(len: Int): (Int, Int) = {
      val curSize = encryptor(Seq.fill(len)(0.toByte)).length
      if(startSize != curSize) {
        val blockSize = curSize - startSize
        (blockSize, startSize - len)
      } else
        findBlockSizeInner(len + 1)
    }
    findBlockSizeInner(1)
  }

  def decryptSuffix(encryptor: Encryptor): Seq[Byte] = {
    type EncMap = Map[Seq[Byte], Seq[Byte]]

    def getOrFetch(map: EncMap, prefix: Seq[Byte]): (EncMap, Seq[Byte]) = {
      if(map.contains(prefix))
        (map, map(prefix))
      else {
        val data = encryptor(prefix)
        (map + (prefix -> data), data)
      }
    }

    val (blockSize, textLen) = findBlockSize(encryptor)

    @tailrec
    def decryptByte(map: EncMap = Map[Seq[Byte], Seq[Byte]](), acc: Seq[Byte] = Seq()): Seq[Byte] = {
      if(acc.length == textLen)
        acc
      else {
        val curBlock = acc.length / blockSize
        val prefixLen = blockSize - (acc.length % blockSize) - 1
        val (map2, beforeAll) = getOrFetch(map, Seq.fill(prefixLen)('A'.toByte))
        val before = beforeAll.slice(curBlock * blockSize, (curBlock + 1) * blockSize)

        val prefix = (Seq.fill(blockSize)('A'.toByte) ++ acc).takeRight(blockSize - 1)
        @tailrec
        def getByte(map: EncMap, byte: Byte = 0): (EncMap, Byte) = {
          val (newMap, dec) = getOrFetch(map, prefix :+ byte)
          if(before == dec.slice(0, blockSize))
            (newMap, byte)
          else
            getByte(newMap, (byte + 1).toByte)
        }

        val (map3, byte) = getByte(map2)
        decryptByte(map3, acc :+ byte)
      }
    }

    if(decOracle(encryptor(checkOracleText)) != EncMethod.ECB)
      Seq()
    else
      decryptByte()
  }

  def decryptSuffixWithPrefix(encryptor: Encryptor): Seq[Byte] = {
    /* We don't care how long the prefix is, we just want it to be a multiple of 16.
     * We know it is a multiple of 16 when we can change the last byte of our padding
     * and change block x, but adding a new byte effects block x+1, and not x.
     */

    val (blockSize, _) = findBlockSize(encryptor)

    @tailrec
    def findBlocks(a: Seq[Byte], b: Seq[Byte], block: Int = 0): Int = {
      val from = block * blockSize
      val to = from + blockSize
      if(a.slice(from, to) == b.slice(from, to))
        findBlocks(a, b, block + 1)
      else
        block + 1 // Everything up to and including this block is padding
    }

    val enc1 = encryptor(Seq(1))
    val enc2 = encryptor(Seq(2))
    val blocks = findBlocks(enc1, enc2)

    val to = blocks * blockSize
    val from = to - blockSize

    @tailrec
    def getPadding(enc1: Seq[Byte], acc: Seq[Byte] = Seq(1)): Seq[Byte] = {
      val acc2 = 1.toByte +: acc
      val enc2 = encryptor(acc2)
      if(enc1.slice(from, to) == enc2.slice(from, to))
        acc
      else
        getPadding(enc2, acc2)
    }

    // We start by adding one char to see how many full blocks the prefix is.

    val padding = getPadding(enc1)

    val encryptor2 = (prefix: Seq[Byte]) => encryptor(padding ++ prefix).splitAt(blockSize * blocks)._2
    decryptSuffix(encryptor2)
  }

  def checkDecryptSuffix(text: Seq[Byte]): Boolean = {
    val key = randomString(16)
    val encryptor = (prefix: Seq[Byte]) => encrypt(padPKCS7(prefix ++ text, 16), key)
    val decrypted = decryptSuffix(encryptor)

    text == decrypted
  }

  def checkDecryptSuffixWithPrefix(text: Seq[Byte]): Boolean = {
    val key = randomString(16)
    val randomPrefix = randomBytes(Random.nextInt(49))
    val encryptor = (prefix: Seq[Byte]) => encrypt(padPKCS7(randomPrefix ++ prefix ++ text, 16), key)
    val decrypted = decryptSuffixWithPrefix(encryptor)

    text == decrypted
  }
}
