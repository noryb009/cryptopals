import org.scalatest.FunSpec

import scala.util.Random

class Set5 extends FunSpec {
  it("C33") {
    val keyA = DiffieHellman.generateKeyPair()
    val keyB = DiffieHellman.generateKeyPair()
    assert(DiffieHellman.generateSession(keyB.pub, keyA.priv) == DiffieHellman.generateSession(keyA.pub, keyB.priv))
  }

  it("C34") {
    val str = AES.randomString(Random.nextInt(48) + 16)
    assert(DiffieHellman.EchoBot.testEchoBot(str).get == str)

    assert(DiffieHellman.EchoBot.mBot(str).get == str)
  }

  it("C35") {
    val str = AES.randomString(Random.nextInt(48) + 16)

    assert(DiffieHellman.EchoBot.mBotG1(str).get == str)
    assert(DiffieHellman.EchoBot.mBotGP(str).get == str)
    assert(DiffieHellman.EchoBot.mBotGPm1(str).get == str)
  }

  it("C36") {
    assert(SRP.client)
  }

  it("C37") {
    assert(SRP.badClient)
  }

  it("C38") {
    assert(SRP.simpleClient)
  }

  it("C39") {
    val data = Utils.stringToBinary(AES.randomString(16)) // Binary must start with 0 bit to be positive
    val kp = RSA.genKeyPair()
    val enc = kp.toPub.encrypt(data)
    val dec = kp.decrypt(enc).toByteArray.toSeq
    assert(dec == data)
  }

  it("C40") {
    val data = BigInt(128, Random)
    val encryptor = () => {
      val kp = RSA.genKeyPair()
      (kp.toPub, kp.toPub.encrypt(data))
    }
    val a = RSA.broadcastAttack(encryptor)
    assert(a.get == data)
  }
}
