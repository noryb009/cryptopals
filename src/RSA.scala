import scala.annotation.tailrec
import scala.util.Random

object RSA {
  case class RSAKey(e: BigInt, d: BigInt, n: BigInt)
  case class RSAPub(k: RSAKey) {
    val e = k.e
    val n = k.n
  }

  val e = BigInt(3)

  def EGCD(a: BigInt, b: BigInt): (BigInt, BigInt) = {
    case class RST(r: BigInt, s: BigInt, t: BigInt)

    @tailrec
    def inner(s0: RST, s1: RST): (BigInt, BigInt) = {
      if(s1.r == BigInt(0))
        (s0.s, s0.t)
      else {
        val q = s0.r / s1.r
        inner(s1, RST(s0.r - q * s1.r, s0.s - q * s1.s, s0.t - q * s1.t))
      }
    }

    inner(RST(a, 1, 0), RST(b, 0, 1))
  }

  def invMod(a: BigInt, m: BigInt): BigInt = {
    val (x, _) = EGCD(a, m)
    (x % m + m) % m
  }

  @tailrec
  def getPrime(size: Int): BigInt = {
    val p = BigInt.probablePrime(size, Random)
    if(p % e == 1)
      getPrime(size)
    else
      p
  }

  def genKeyPair(size: Int = 128): RSAKey = {
    val p = getPrime(size)
    val q = getPrime(size)
    val n = p * q
    val et = (p - 1) * (q - 1)
    val e = 3
    val d = invMod(e, et)

    RSAKey(e, d, n)
  }

  def encrypt(data: BigInt, key: RSAPub): BigInt =
    data.modPow(key.e, key.n)

  def encrypt(data: BigInt, key: RSAKey): BigInt =
    encrypt(data, RSAPub(key))

  def encrypt(data: Seq[Byte], key: RSAPub): BigInt =
    encrypt(BigInt(data.toArray), key)

  def encrypt(data: Seq[Byte], key: RSAKey): BigInt =
    encrypt(BigInt(data.toArray), RSAPub(key))

  def decrypt(data: BigInt, key: RSAKey): BigInt =
    data.modPow(key.d, key.n)

  def crt(values: Seq[(BigInt, BigInt)]): (BigInt, BigInt) = {
    val nTotal = values.foldLeft(BigInt(1)){case (acc, (_, n)) => n * acc}

    val sum = values.map{case (c, n) =>
      val nExclude = nTotal / n
      val q = c * nExclude * invMod(nExclude, n)
      q
    }.sum % nTotal

    (sum, nTotal)
  }

  def eRootFloor(n: BigInt): BigInt = {
    @tailrec
    def inner(low: BigInt, high: BigInt): BigInt = {
      if(low > high) {
        val midp = low.pow(e.toInt)
        if(midp > n)
          high
        else
          low
      } else {
        val mid = (low + high) / 2
        val midp = mid.pow(e.toInt)
        if(midp == n)
          mid
        else if(midp > n)
          inner(low, mid - 1)
        else
          inner(mid + 1, high)
      }
    }

    inner(0, n)
  }

  def eRoot(n: BigInt): Option[BigInt] = {
    val floor = eRootFloor(n)
    if(floor.pow(e.toInt) == n)
      Some(floor)
    else
      None
  }

  def broadcastAttack(encryptor: () => (RSAPub, BigInt)): Option[BigInt] = {
    val encs = (0 until e.toInt).map(_ => encryptor())

    val (baseVal, nTotal) = crt(encs.map{case (pub, enc) => (enc, pub.n)})

    @tailrec
    def tryRoot(n: BigInt, tries: Int = 10): Option[BigInt] = {
      eRoot(n) match {
        case None =>
          if(tries > 0)
            tryRoot(n + nTotal, tries - 1)
          else
            None
        case x => x
      }
    }

    tryRoot(baseVal)
  }

  def messageRecoveryOracle(c: BigInt, pub: RSAPub, decryptor: BigInt => BigInt): String = {
    val s = BigInt(pub.n.bitLength, Random) % (pub.n - 2) + 2
    val cPrime = (s.modPow(pub.e, pub.n) * c) % pub.n
    val pPrime = decryptor(cPrime)
    val p = (pPrime * s.modInverse(pub.n)) % pub.n

    Utils.binaryToString(p.toByteArray)
  }

  object Sign {
    val explen = 1024 / 8
    val hashlen = 128 / 8
    val asn1MD4 = Seq(0x01, 0x03) // or something like that
    val endOfPadding = 0x00.toByte +: asn1MD4.map(_.toByte)

    def padAndSign(data: Seq[Byte], kp: RSAKey): BigInt = {
      val hash = Hash.md4(data)
      val dec = (Seq(0x0, 0x1) ++ Seq.fill(explen - 2 - hashlen - 1 - asn1MD4.length)(0xff) ++ Seq(0x00) ++ asn1MD4).map(_.toByte) ++ hash
      decrypt(BigInt(dec.toArray), kp)
    }

    def validateSignature(data: Seq[Byte], signature: BigInt, pub: RSAPub): Boolean = {
      val decWrongSize = encrypt(signature, pub).toByteArray
      val dec = Seq.fill[Byte](explen - decWrongSize.length)(0) ++ decWrongSize

      // EB = 00 || BT (01) || PS (FF * (k-3-|D|)) || 00 || D

      if(dec.length != explen || !dec.startsWith(Seq(0x0, 0x1, 0xff).map(_.toByte)))
        false
      else {
        val endStart = dec.slice(2, explen).indexOf(0x00.toByte) + 2
        val hashStart = endStart + endOfPadding.length
        if(dec.slice(endStart, hashStart) != endOfPadding)
          false
        else {
          val hash = Hash.md4(data)
          hash == dec.slice(hashStart, hashStart + hash.length)
        }
      }
    }

    def forgeSignature(data: Seq[Byte], pub: RSAPub): BigInt = {
      val hash = Hash.md4(data)
      val start = (Seq(0x0, 0x1, 0xff, 0x00) ++ asn1MD4).map(_.toByte) ++ hash
      val end = Seq.fill(explen - start.length)(0xff.toByte)

      val max = BigInt((start ++ end).toArray)
      eRootFloor(max)
    }
  }
}
