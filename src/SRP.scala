import scala.util.Random

object SRP {
  val N = BigInt.probablePrime(128, Random)
  val g = BigInt(2)
  val k = 3
  val email = AES.randomString(Random.nextInt(32) + 5)
  val P = AES.randomString(Random.nextInt(32) + 5)

  def shaStrInt(str: String): BigInt =
    BigInt(Hex.encode(Hash.sha1(Utils.stringToBinary(str))), 16)

  def calcX(salt: Int, password: String): BigInt =
    shaStrInt(salt.toString ++ password)

  def calcU(aPub: BigInt, bPub: BigInt): BigInt =
    shaStrInt(aPub.toString ++ bPub.toString)

  def calcV(x: BigInt) =
    g.modPow(x, N)

  def sToKey(s: BigInt): String =
    Hex.encode(Hash.sha1(Utils.stringToBinary(s.toString)))

  def serverInit = {
    val salt = Random.nextInt
    val x = calcX(salt, P)
    val v = calcV(x)

    def sendEmail(I: String, aPub: BigInt) = {
      val kp = DiffieHellman.generateKeyPair(N, g)
      val bPub = kp.pub + k * v

      val u = calcU(aPub, bPub)
      val s = (aPub * v.modPow(u, N)).modPow(kp.priv, N)

      val key = sToKey(s)

      def checkHMAC(clientHMAC: Seq[Byte]): Boolean = {
        val serverHMAC = Hash.sha1HMAC(s.toByteArray, key)
        clientHMAC == serverHMAC
      }

      (salt, bPub, (c: Seq[Byte]) => checkHMAC(c))
    }
    (I: String, A: BigInt) => sendEmail(I, A)
  }

  def clientLogin(password: String, bad: Boolean): Boolean = {
    val sendEmail = serverInit
    val kp = if(bad) DiffieHellman.KeyPair(N*Random.nextInt(5), 0) else DiffieHellman.generateKeyPair(N, g)
    val (salt, bPub, checkHMAC) = sendEmail(email, kp.pub)
    val u = calcU(kp.pub, bPub)
    val x = calcX(salt, password)
    val v = calcV(x)
    val s = if(bad) BigInt(0) else (bPub - k * v).modPow(kp.priv + u * x, N)

    val key = sToKey(s)
    val hmac = Hash.sha1HMAC(s.toByteArray, key)

    checkHMAC(hmac)
  }

  def client: Boolean =
    clientLogin(P, bad = false)

  def badClient: Boolean =
    clientLogin("", bad = true)

  val badSalt = 0
  val badPriv = 2
  val dictSize = 100 // could be any dictionary

  def crackPassword(clientHMAC: Seq[Byte], aPub: BigInt): String = {
    (0 until dictSize).par.find{p =>
      val x = calcX(badSalt, p.toString)
      val v = calcV(x)
      val s = (aPub * v).modPow(badPriv, N)

      val key = sToKey(s)
      val serverHMAC = Hash.sha1HMAC(s.toByteArray, key)
      serverHMAC == clientHMAC
    }.getOrElse(-1).toString
  }

  def badSimpleServerInit = {
    val salt = badSalt

    def sendEmail(I: String, aPub: BigInt) = {
      val b = badPriv
      val kp = DiffieHellman.KeyPair(g.modPow(b, N), b)
      val u = 1

      def checkHMAC(clientHMAC: Seq[Byte]): String =
        crackPassword(clientHMAC, aPub)

      (salt, kp.pub, u, (c: Seq[Byte]) => checkHMAC(c))
    }

    (I: String, aPub: BigInt) => sendEmail(I, aPub)
  }

  def simpleClient = {
    val password = Random.nextInt(dictSize).toString
    val sendEmail = badSimpleServerInit
    val kp = DiffieHellman.generateKeyPair(N, g)
    val (salt, bPub, u, checkHMAC) = sendEmail(email, kp.pub)
    val x = calcX(salt, password)
    val s = bPub.modPow(kp.priv + u * x, N)

    val key = sToKey(s)
    val hmac = Hash.sha1HMAC(s.toByteArray, key)

    checkHMAC(hmac) == password
  }
}
