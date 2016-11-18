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

  def client: Boolean = {
    val sendEmail = serverInit
    val kp = DiffieHellman.generateKeyPair(N, g)
    val (salt, bPub, checkHMAC) = sendEmail(email, kp.pub)
    val u = calcU(kp.pub, bPub)
    val x = calcX(salt, P)
    val v = calcV(x)
    val s = (bPub - k * v).modPow(kp.priv + u * x, N)

    val key = sToKey(s)
    val hmac = Hash.sha1HMAC(s.toByteArray, key)

    checkHMAC(hmac)
  }
}
