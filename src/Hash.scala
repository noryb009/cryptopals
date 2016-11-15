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

  def md4Padding(dataLength: Int): Seq[Byte] = {
    val padding = sha1Padding(dataLength)
    val (zeros, len) = padding.splitAt(padding.length - 8)
    zeros ++ len.reverse
  }

  def sha1CalcChunk(chunk: Seq[Byte], h: Seq[Int]): Seq[Int] = {
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

  def md4CalcChunk(chunk: Seq[Byte], Q: Seq[Int]): Seq[Int] = {
    val k = Seq(
      0x00000000,
      0x5a827999,
      0x6ed9eba1
    )

    val shift = Seq(
      Seq(3, 7, 11, 19),
      Seq(3, 5, 9, 13),
      Seq(3, 9, 11, 15)
    )

    val a = 0
    val b = 1
    val c = 2
    val d = 3

    def F(a: Int, b: Int, c: Int): Int = a & b | (~a & c)
    def G(a: Int, b: Int, c: Int): Int = (a & b) | (a & c) | (b & c)
    def H(a: Int, b: Int, c: Int): Int = a ^ b ^ c

    val X = chunk
      .grouped(4)
      .map(x => bitsToInt(x.reverse))
      .toIndexedSeq

    val letters1 = (0 until 16).foldLeft(Q){case (q, i) => {
      Seq(
        q(d),
        rotl(q(a) + F(q(b), q(c), q(d)) + X(i) + k.head, shift.head(i % 4)),
        q(b),
        q(c)
      )
    }}

    val xInd2 = IndexedSeq(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    val letters2 = (0 until 16).foldLeft(letters1){case (q, i) =>
      Seq(
        q(d),
        rotl(q(a) + G(q(b), q(c), q(d)) + X(xInd2(i)) + k(1), shift(1)(i % 4)),
        q(b),
        q(c)
      )
    }

    val xInd3 = IndexedSeq(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
    val letters3 = (0 until 16).foldLeft(letters2){case (q, i) =>

      Seq(
        q(d),
        rotl(q(a) + H(q(b), q(c), q(d)) + X(xInd3(i)) + k(2), shift(2)(i % 4)),
        q(b),
        q(c)
      )
    }

    Q.zip(letters3).map{case (x, y) => x + y}
  }

  def md4FromQ(data: Seq[Byte], Q: Seq[Int]): Seq[Byte] =
    data
      .grouped(64)
      .foldLeft(Q){case (qVal, chunk) => md4CalcChunk(chunk, qVal)}
      .flatMap(x => intTo32Bit(x).reverse)

  def md4(data: Seq[Byte]): Seq[Byte] = {
    val Q = Seq(
      0x67452301,
      0xefcdab89,
      0x98badcfe,
      0x10325476
    )

    val padding = md4Padding(data.length)
    md4FromQ(data ++ padding, Q)
  }

  def md4HMAC(message: Seq[Byte], key: String): Seq[Byte] =
    md4(Utils.stringToBinary(key) ++ message)

  def md4HMACCheck(message: Seq[Byte], key: String, hmac: Seq[Byte]): Boolean =
    md4HMAC(message, key) == hmac

  def appendMD4(hmac: Seq[Byte], suffix: Seq[Byte], origSize: Int): Seq[Byte] = {
    val Q = hmac
      .grouped(4)
      .map(x => bitsToInt(x.reverse))
      .toSeq
    val padding = md4Padding(origSize + sha1Padding(origSize).length + suffix.length)
    md4FromQ(suffix ++ padding, Q)
  }
}
