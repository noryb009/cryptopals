import scala.util.Random

object DiffieHellman {
  val nistP = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" +
              "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" +
              "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" +
              "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" +
              "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" +
              "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" +
              "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" +
              "fffffffffffff"
  val np = BigInt(nistP, 16)
  val ng = BigInt(2)

  case class KeyPair(pub: BigInt, priv: BigInt)

  def generateKeyPair(p: BigInt = np, g: BigInt = ng): KeyPair = {
    val priv = BigInt(p.bitLength, Random) % p
    val pub = g.modPow(priv, p)
    KeyPair(pub, priv)
  }

  def generateSession(otherPub: BigInt, priv: BigInt, p: BigInt = np): BigInt =
    otherPub.modPow(priv, p)

  object EchoBot {
    def sessionToKey(s: BigInt) =
      Hex.encode(Hash.sha1(s.toByteArray)).take(16)

    case class BotStatus(p: BigInt, kp: KeyPair, otherPub: BigInt) {
      val key =
        sessionToKey(generateSession(otherPub, kp.priv, p))
    }

    def startA: (BotStatus, (BigInt, BigInt, BigInt)) = {
      val bot = BotStatus(np, generateKeyPair(np, ng), 0)
      (bot, (np, ng, bot.kp.pub))
    }

    def startB(params: (BigInt, BigInt, BigInt)): (BotStatus, BigInt) = {
      val (p, g, otherPub) = params
      val bot = BotStatus(p, generateKeyPair(p, g), otherPub)
      (bot, bot.kp.pub)
    }

    def finishA(botStatus: BotStatus, otherPub: BigInt): BotStatus =
      BotStatus(botStatus.p, botStatus.kp, otherPub)

    def sendMessage(bot: BotStatus, text: String): Seq[Byte] = {
      val iv = AES.randomBytes(16)
      iv ++ AES.encryptCBC(AES.padPKCS7(Utils.stringToBinary(text)), bot.key, Some(iv))
    }

    def recvMessage(key: String, data: Seq[Byte]): Option[String] = {
      val (iv, enc) = data.splitAt(16)
      AES.unpadPKCS7(AES.decryptCBC(enc, key, Some(iv))).map(Utils.binaryToString)
    }

    def recvMessage(bot: BotStatus, data: Seq[Byte]): Option[String] =
      recvMessage(bot.key, data)

    def echoMessage(bot: BotStatus, data: Seq[Byte]): Seq[Byte] = {
      val text = recvMessage(bot, data).get
      sendMessage(bot, text)
    }

    def testEchoBot(message: String): Option[String] = {
      val (aPrime, initB) = startA
      val (b, initA) = startB(initB)
      val a = finishA(aPrime, initA)

      val encA = sendMessage(a, message)
      val encB = echoMessage(b, encA)
      recvMessage(a, encB)
    }

    def mBot(message: String): Option[String] = {
      val (aPrime, initB) = startA
      val (b, initA) = startB(initB._1, initB._2, initB._1)
      val a = finishA(aPrime, initB._1)

      val encA = sendMessage(a, message)
      val encB = echoMessage(b, encA)
      val decB = recvMessage(a, encB)
      if(decB.getOrElse("") != message)
        None
      else {
        // Note that key is sha1(0)
        val key = sessionToKey(0)
        val mA = recvMessage(key, encA)
        val mB = recvMessage(key, encB)

        if(mA == mB)
          mA
        else
          None
      }
    }

    def mBotG1(message: String): Option[String] = {
      val (aPrime, initB) = startA
      val (b, initA) = startB(initB._1, 1, initB._3)
      val a = finishA(aPrime, initA)

      val encA = sendMessage(a, message)

      // Note that key is sha1(1)
      val key = sessionToKey(1)
      recvMessage(key, encA)
    }

    def mBotGP(message: String): Option[String] = {
      val (aPrime, initB) = startA
      val (b, initA) = startB(initB._1, initB._1, initB._3)
      val a = finishA(aPrime, initA)

      val encA = sendMessage(a, message)
      // Note that key is sha1(0)
      val key = sessionToKey(0)
      recvMessage(key, encA)
    }

    def mBotGPm1(message: String): Option[String] = {
      val (aPrime, initB) = startA
      val (b, initA) = startB(initB._1, initB._1 - 1, initB._3)
      val a = finishA(aPrime, initA)

      val encA = sendMessage(a, message)
      // Note that B's public key is either 1 or p-1, if the private key is even or odd, respectively
      // Similar math is done to get the session key, so it is either sha1(1) or sha(p-1)
      val keyA = sessionToKey(1)
      val keyB = sessionToKey(initB._1 - 1)
      recvMessage(keyA, encA) match {
        case None => recvMessage(keyB, encA)
        case x => x
      }
    }
  }
}
