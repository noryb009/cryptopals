import scala.annotation.tailrec
import scala.util.Random

object RSA {
  case class RSAKey(e: BigInt, d: BigInt, n: BigInt) {
    def decrypt(data: BigInt): BigInt =
      RSA.decrypt(data, this)

    def toPub: RSAPub =
      RSAPub(e, n)
  }
  case class RSAPub(e: BigInt, n: BigInt) {
    def encrypt(data: Seq[Byte]): BigInt =
      RSA.encrypt(data, this)

    def encrypt(data: BigInt): BigInt =
      RSA.encrypt(data, this)
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
  def getPrime(size: Int, not: Option[BigInt] = None): BigInt = {
    val p = BigInt.probablePrime(size, Random)
    if(not.contains(p) || p % e == 1)
      getPrime(size, not)
    else
      p
  }

  def genKeyPair(size: Int = 128): RSAKey = {
    val p = getPrime(size)
    val q = getPrime(size, Some(p))
    val n = p * q
    val et = (p - 1) * (q - 1)
    val e = 3
    val d = invMod(e, et)

    RSAKey(e, d, n)
  }

  def encrypt(data: BigInt, key: RSAPub): BigInt =
    data.modPow(key.e, key.n)

  def encrypt(data: Seq[Byte], key: RSAPub): BigInt =
    encrypt(BigInt(data.toArray), key)

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
      kp.decrypt(BigInt(dec.toArray))
    }

    def validateSignature(data: Seq[Byte], signature: BigInt, pub: RSAPub): Boolean = {
      val decWrongSize = pub.encrypt(signature).toByteArray
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

  def isEven(data: BigInt, kp: RSAKey): Boolean =
    kp.decrypt(data) % 2 == BigInt(0)

  def isEvenAttack(enc: BigInt, pub: RSAPub, isEven: BigInt => Boolean): BigInt = {
    val two = BigInt(2)
    val rsaTwo = two.modPow(pub.e, pub.n)
    @tailrec
    def binSearch(enc: BigInt, min: BigInt, max: BigInt, mult: BigInt, incs: BigInt): BigInt = {
      //println(max)
      if(min >= max)
        max
      else {
        val dbl = enc * rsaTwo
        val pivot = pub.n * (incs + 1) / mult
        if(isEven(dbl)) // no wrap
          binSearch(dbl, min, pivot, mult * 2, incs * 2)
        else // wrap around
          binSearch(dbl, pivot + 1, max, mult * 2, incs * 2 + 2)
      }
    }

    binSearch(enc, 0, pub.n - 1, 2, 0)
  }
}
