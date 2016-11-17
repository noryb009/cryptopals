import org.scalatest.FunSpec

import scala.util.Random

class Set5 extends FunSpec {
  it("C33") {
    val keyA = DiffieHellman.generateKeyPair()
    val keyB = DiffieHellman.generateKeyPair()
    assert(DiffieHellman.generateSession(keyB.pub, keyA.priv) == DiffieHellman.generateSession(keyA.pub, keyB.priv))
  }

  it("C34") {
    val str = AES.randomString(Random.nextInt(48))
    assert(DiffieHellman.EchoBot.testEchoBot(str) == str)

    assert(DiffieHellman.EchoBot.mBot(str) == str)
  }
}
