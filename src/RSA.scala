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

  def eRoot(n: BigInt): Option[BigInt] = {
    @tailrec
    def inner(low: BigInt, high: BigInt): Option[BigInt] = {
      if(low > high)
        None
      else {
        val mid = (low + high) / 2
        val midp = mid.pow(e.toInt)
        if(midp == n)
          Some(mid)
        else if(midp > n)
          inner(low, mid - 1)
        else
          inner(mid + 1, high)
      }
    }

    inner(0, n)
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
}
