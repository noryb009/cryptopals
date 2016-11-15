import scala.annotation.tailrec

object Hash {
  // Int is 32 bits
  def intTo32Bit(n: Int): Seq[Byte] = {
    def getByte(c: Int): Byte = ((n >>> (c * 8)) & 0xFF).toByte
    Seq.tabulate[Byte](4)(getByte).reverse
  }

  def intTo64Bit(n: Int): Seq[Byte] =
    Seq.fill[Byte](4)(0) ++ intTo32Bit(n)

  def bitsToInt(s: Seq[Byte]): Int =
    s.reverse.zipWithIndex.map { case (n, i) => (n << (8 * i)) & (0xFF << (8 * i)) }.sum

  def rotl(x: Int, n: Int): Int =
    (x >>> (32 - n)) | (x << n)

  def sha1Padding(dataLength: Int): Seq[Byte] = {
    val padLen = ((64 + 56) - ((dataLength + 1) % 64)) % 64
    0x80.toByte +: (Seq.fill[Byte](padLen)(0) ++ intTo64Bit(dataLength * 8))
  }

  def sha1CalcChunk(chunk: Seq[Byte], h: Seq[Int]) = {
    val a = 0
    val b = 1
    val c = 2
    val d = 3
    val e = 4

    val w = chunk.grouped(4).map(bitsToInt).toIndexedSeq

    @tailrec
    def extend(w: IndexedSeq[Int]): IndexedSeq[Int] =
      if (w.length == 80)
        w
      else
        extend(rotl(w(2) ^ w(7) ^ w(13) ^ w(15), 1) +: w)

    val w2 = extend(w.reverse).reverse

    val letters = w2.zipWithIndex.foldLeft(h) { case (h, (w, i)) => {
      val (f, k) =
        if (i <= 19)
          ((h(b) & h(c)) | (~h(b) & h(d)), 0x5A827999)
        else if (i <= 39)
          (h(b) ^ h(c) ^ h(d), 0x6ED9EBA1)
        else if (i <= 59)
          ((h(b) & h(c)) | (h(b) & h(d)) | (h(c) & h(d)), 0x8F1BBCDC)
        else
          (h(b) ^ h(c) ^ h(d), 0xCA62C1D6)
      Seq(
        rotl(h(a), 5) + f + h(e) + k + w,
        h(a),
        rotl(h(b), 30),
        h(c),
        h(d)
      )
    }
    }
    h.zip(letters).map { case (x, y) => x + y }
  }

  def sha1FromH(data: Seq[Byte], h: Seq[Int]): Seq[Byte] =
    data
      .grouped(64)
      .foldLeft(h){case (hVal, chunk) => sha1CalcChunk(chunk, hVal)}
      .flatMap(intTo32Bit)

  def sha1(data: Seq[Byte]): Seq[Byte] = {
    val h = Seq(
      0x67452301,
      0xEFCDAB89,
      0x98BADCFE,
      0x10325476,
      0xC3D2E1F0
    )

    val padding = sha1Padding(data.length)
    sha1FromH(data ++ padding, h)
  }

  def sha1HMAC(message: Seq[Byte], key: String): Seq[Byte] =
    sha1(Utils.stringToBinary(key) ++ message)

  def sha1HMACCheck(message: Seq[Byte], key: String, sha: Seq[Byte]): Boolean =
    sha1HMAC(message, key) == sha

  def appendSha1(sha: Seq[Byte], suffix: Seq[Byte], origSize: Int): Seq[Byte] = {
    val h = sha
      .grouped(4)
      .map(bitsToInt)
      .toSeq
    val padding = sha1Padding(origSize + sha1Padding(origSize).length + suffix.length)
    sha1FromH(suffix ++ padding, h)
  }
}
