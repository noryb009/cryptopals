import scala.util.Random

object DSA {
  val pStr =
    "800000000000000089e1855218a0e7dac38136ffafa72eda7" +
    "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6" +
    "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe" +
    "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2" +
    "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87" +
    "1a584471bb1"
  val np = BigInt(pStr, 16)
  val qStr = "f4f47f05794b256174bba6e9b396a7707e563c5b"
  val nq = BigInt(qStr, 16)
  val gStr =
    "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119" +
    "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5" +
    "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047" +
    "0f5b64c36b625a097f1651fe775323556fe00b3608c887892" +
    "878480e99041be601a62166ca6894bdd41a7054ec89f756ba" +
    "9fc95302291"
  val ng = BigInt(gStr, 16)

  case class KeyPub(y: BigInt, p: BigInt, q: BigInt, g: BigInt) {
    def validate(data: Seq[Byte], sig: Signature) =
      DSA.validateSignature(data, this, sig)
  }
  case class KeyPair(x: BigInt, p: BigInt, q: BigInt, g: BigInt) {
    lazy val y = g.modPow(x, p)
    def sign(data: Seq[Byte]) =
      DSA.sign(data, this)

    def toPub: KeyPub =
      KeyPub(y, p, q, g)
  }
  case class SubKey(k: BigInt, p: BigInt, q: BigInt, g: BigInt) {
    val kInv = k.modInverse(q)
  }
  case class Signature(r: BigInt, s: BigInt)

  def genKeyPair(p: BigInt = np, q: BigInt = nq, g: BigInt = ng): KeyPair = {
    val c = BigInt(q.bitLength + 64, Random).abs
    val x = c.mod(q - 1) + 1

    KeyPair(x, p, q, g)
  }

  def genSubKey(p: BigInt = np, q: BigInt = nq, g: BigInt = ng): SubKey = {
    val c = BigInt(q.bitLength + 64, Random).abs
    val k = c.mod(q - 1) + 1
    SubKey(k, p, q, g)
  }

  val hashBits = 160
  def hashValue(hash: Seq[Byte], q: BigInt): BigInt = {
    val minPos = Seq(q.bitLength, hashBits).min
    BigInt(1, hash.take(minPos).toArray)
  }

  def sign(data: Seq[Byte], kp: KeyPair, hash: Option[Seq[Byte]] = None, kkOpt: Option[SubKey] = None): (SubKey, Signature) = {
    val kk = kkOpt.getOrElse(genSubKey(kp.p, kp.q, kp.g))
    val hashVal = hash.getOrElse(Hash.sha1(data))
    val r = kp.g.modPow(kk.k, kp.p) % kp.q
    val z = hashValue(hashVal, kp.q)
    val s = (kk.kInv * (z + kp.x * r)) % kp.q
    (kk, Signature(r, s))
  }

  def validateSignature(data: Seq[Byte], pub: KeyPub, sig: Signature): Boolean = {
    if(sig.r < 0 || sig.r >= pub.q || sig.s < 0 || sig.s >= pub.q)
      false
    else {
      val w = sig.s.modInverse(pub.q)
      val z = hashValue(Hash.sha1(data), pub.q)
      val u1 = (z * w) % pub.q
      val u2 = (sig.r * w) % pub.q
      val v = (pub.g.modPow(u1, pub.p) * pub.y.modPow(u2, pub.p)) % pub.p % pub.q
      v == sig.r
    }
  }

  def inverseKeyHash(z: BigInt, subKey: SubKey, sig: Signature): KeyPair = {
    val x = ((sig.s * subKey.k) - z) * sig.r.modInverse(subKey.q) % subKey.q
    KeyPair(x, subKey.p, subKey.q, subKey.g)
  }

  def inverseKey(data: Seq[Byte], subKey: SubKey, sig: Signature): KeyPair = {
    val z = hashValue(Hash.sha1(data), subKey.q)
    val x = ((sig.s * subKey.k) - z) * sig.r.modInverse(subKey.q) % subKey.q
    KeyPair(x, subKey.p, subKey.q, subKey.g)
  }

  def findKey(data: Seq[Byte], sig: Signature, possible: Stream[Int]): Option[KeyPair] =
    possible
      .flatMap{k =>
        try {
          Some(SubKey(k, np, nq, ng))
        } catch {
          case _: ArithmeticException => None
        }
      }.map{k => (k, inverseKey(data, k, sig))}
      .find{case (k, x) => sig == sign(data, x, None, Some(k))._2}
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
      val k = modSub(m1.hashValue, m2.hashValue) * modSub(m1.sig.s, m2.sig.s).modInverse(nq) % nq
      Some(SubKey(k, np, nq, ng))
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

  def zeroMagicSignature: Signature =
    DSA.Signature(0, 1)

  def oneMagicSignature(pub: KeyPub): Signature = {
    val z = BigInt(pub.q.bitLength, Random) % (pub.q - 1) + 1
    val r = pub.y.modPow(z, pub.p) % pub.q
    val s = r * z.modInverse(pub.q) % pub.q
    DSA.Signature(r, s)
  }
}
