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

  it("C42") {
    val kp = RSA.genKeyPair(1024)
    val str = "hi mom"
    val data = Utils.stringToBinary(str)
    val signature = RSA.Sign.padAndSign(data, kp)
    assert(RSA.Sign.validateSignature(data, signature, RSA.RSAPub(kp)))

    val (dataA, dataB) = data.splitAt(data.length - 1)
    assert(!RSA.Sign.validateSignature(dataA :+ (dataB.head ^ 1).toByte, signature, RSA.RSAPub(kp)))

    val forgedSignature = RSA.Sign.forgeSignature(data, RSA.RSAPub(kp))
    assert(RSA.Sign.validateSignature(data, forgedSignature, RSA.RSAPub(kp)))
  }
}
