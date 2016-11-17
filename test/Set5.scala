import org.scalatest.FunSpec

class Set5 extends FunSpec {
  it("C33") {
    val keyA = DiffieHellman.generateKeyPair()
    val keyB = DiffieHellman.generateKeyPair()
    assert(DiffieHellman.generateSession(keyB.pub, keyA.priv) == DiffieHellman.generateSession(keyA.pub, keyB.priv))
  }
}
