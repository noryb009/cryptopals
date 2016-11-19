import scala.annotation.tailrec
import scala.util.Random

object DSA {
  val pStr =
    "800000000000000089e1855218a0e7dac38136ffafa72eda7" +
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6" +
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe" +
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2" +
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87" +
    "1a584471bb1"
  val p = BigInt(pStr, 16)
  val qStr = "f4f47f05794b256174bba6e9b396a7707e563c5b"
  val q = BigInt(qStr, 16)
  val gStr =
    "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119" +
    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5" +
    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047" +
    "0f5b64c36b625a097f1651fe775323556fe00b3608c887892" +
    "878480e99041be601a62166ca6894bdd41a7054ec89f756ba" +
    "9fc95302291"
  val g = BigInt(gStr, 16)

  case class KeyPub(y: BigInt) {
    def validate(data: Seq[Byte], sig: Signature) =
      DSA.validateSignature(data, this, sig)
  }
  case class KeyPair(x: BigInt) {
    lazy val y = g.modPow(x, p)
    def sign(data: Seq[Byte]) =
      DSA.sign(data, this)

    def toPub: KeyPub =
      KeyPub(y)
  }
  case class SubKey(k: BigInt) {
    val kInv = k.modInverse(q)
  }
  case class Signature(r: BigInt, s: BigInt)

  def genKeyPair: KeyPair = {
    val c = BigInt(q.bitLength + 64, Random).abs
    val x = c.mod(q - 1) + 1

    KeyPair(x)
  }

  def genSubKey: SubKey = {
    val c = BigInt(q.bitLength + 64, Random).abs
    val k = c.mod(q - 1) + 1
    SubKey(k)
  }

  val hashBits = 160
  val minPos = Seq(q.bitLength, hashBits).min

  def hashValue(hash: Seq[Byte]): BigInt =
    BigInt(1, hash.take(minPos).toArray)

  @tailrec
  def sign(data: Seq[Byte], kp: KeyPair, hash: Option[Seq[Byte]] = None, kk: SubKey = genSubKey): (SubKey, Signature) = {
    val hashVal = hash.getOrElse(Hash.sha1(data))
    val r = g.modPow(kk.k, p) % q
    if(r == 0)
      sign(data, kp, Some(hashVal))
    else {
      val z = hashValue(hashVal)
      val s = (kk.kInv * (z + kp.x * r)) % q
      if(s == 0)
        sign(data, kp, Some(hashVal))
      else
        (kk, Signature(r, s))
    }
  }

  def validateSignature(data: Seq[Byte], pub: KeyPub, sig: Signature): Boolean = {
    if(sig.r <= 0 || sig.r >= q || sig.s <= 0 || sig.s >= q)
      false
    else {
      val w = sig.s.modInverse(q)
      val z = hashValue(Hash.sha1(data))
      val u1 = (z * w) % q
      val u2 = (sig.r * w) % q
      val v = (g.modPow(u1, p) * pub.y.modPow(u2, p)) % p % q
      v == sig.r
    }
  }

  def inverseKeyHash(z: BigInt, subKey: SubKey, sig: Signature): KeyPair = {
    val x = ((sig.s * subKey.k) - z) * sig.r.modInverse(q) % q
    KeyPair(x)
  }

  def inverseKey(data: Seq[Byte], subKey: SubKey, sig: Signature): KeyPair = {
    val z = hashValue(Hash.sha1(data))
    val x = ((sig.s * subKey.k) - z) * sig.r.modInverse(q) % q
    KeyPair(x)
  }

  def findKey(data: Seq[Byte], sig: Signature, possible: Stream[Int]): Option[KeyPair] =
    possible
      .flatMap{k =>
        try {
          Some(SubKey(k))
        } catch {
          case _: ArithmeticException => None
        }
      }.map{k => (k, inverseKey(data, k, sig))}
      .find{case (k, x) => sig == sign(data, x, None, k)._2}
      .map(_._2)

  case class SignedMessage(message: String, sig: Signature) {
    val data = Utils.stringToBinary(message)
    val hash = Hash.sha1(data)
    val hashValue = BigInt(1, hash.toArray)
  }

  def readSignedMessages(file: String): Seq[SignedMessage] =
    io.Source.fromFile(file).getLines
      .map(_.split(" ", 2)(1))
      .grouped(4)
      .map{case Seq(msg, s, r, m) => SignedMessage(msg, Signature(BigInt(r), BigInt(s)))}
      .toSeq

  def findReusedSubkey(m1: SignedMessage, m2: SignedMessage): Option[SubKey] = {
    def modSub(a: BigInt, b: BigInt) =
      if(a > b) a - b else b - a

    try {
      val k = modSub(m1.hashValue, m2.hashValue) * modSub(m1.sig.s, m2.sig.s).modInverse(q) % q
      Some(SubKey(k))
    } catch {
      case _: ArithmeticException => None
    }
  }

  def findReusedK(messages: Seq[SignedMessage]): Option[KeyPair] = {
    val messagesI = messages.zipWithIndex
    messagesI.collectFirst(Function.unlift{case (m1, i1) =>
      messagesI.collectFirst(Function.unlift{case (m2, i2) =>
        if(i1 == i2)
          None
        else {
          val subkey = findReusedSubkey(m1, m2)
          subkey.flatMap{k =>
            val a = inverseKey(m1.data, k, m1.sig)
            val b = inverseKey(m2.data, k, m2.sig)
            if(a == b)
              Some(a)
            else
              None
          }
        }
      })
    })
  }
}
