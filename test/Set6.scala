import org.scalatest.FunSpec

class Set6 extends FunSpec {
  it("C41") {
    val data = AES.randomString(16)
    val kp = RSA.genKeyPair()
    val enc = RSA.encrypt(Utils.stringToBinary(data), kp)
    val decryptor = (n: BigInt) => if(n == enc) BigInt(0) else RSA.decrypt(n, kp)

    val dec = RSA.messageRecoveryOracle(enc, RSA.RSAPub(kp), decryptor)
    assert(data == dec)
  }
}
