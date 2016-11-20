import org.scalatest.FunSpec

import scala.util.Random

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

  def matchPrivKey(key: DSA.KeyPair, expHash: String): Boolean =
    Hex.encode(Hash.sha1(key.x.toString(16).getBytes)) == expHash

  it("C43") {
    val data = AES.randomBytes(Random.nextInt(32))
    val kp = DSA.genKeyPair()

    val (kk, sig) = kp.sign(data)
    assert(kp.toPub.validate(data, sig))

    val kpCopy = DSA.inverseKey(data, kk, sig)
    assert(kp.x == kpCopy.x)

    {
      val str =
        "For those that envy a MC it can be hazardous to your health\n" +
          "So be friendly, a matter of life and death, just like a etch-a-sketch\n"
      val data = Utils.stringToBinary(str)
      val rStr = "548099063082341131477253921760299949438196259240"
      val sStr = "857042759984254168557880549501802188789837994940"
      val sig = DSA.Signature(BigInt(rStr), BigInt(sStr))

      //val range = 0 to Math.pow(2, 16).toInt
      val range = 16575 to 16575
      val key = DSA.findKey(data, sig, range.toStream).get

      val expHash = "0954edd5e0afe5542a4adf012611a91912a3ec16"
      val yStr =
        "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4" +
          "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004" +
          "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed" +
          "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b" +
          "bb283e6633451e535c45513b2d33c99ea17"
      val y = BigInt(yStr, 16)

      assert(key.y == y)
      assert(matchPrivKey(key, expHash))
    }
  }

  it("C44") {
    val yStr =
      "2d026f4bf30195ede3a088da85e398ef869611d0f68f07" +
        "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8" +
        "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519" +
        "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430" +
        "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3" +
        "2971c3de5084cce04a2e147821"
    val y = BigInt(yStr, 16)

    val expHash = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    val messages = DSA.readSignedMessages("res/S6C44.txt").toList
    val key = DSA.findReusedK(messages).get
    assert(key.y == y)
    assert(matchPrivKey(key, expHash))
  }

  it("C45") {
    val strings = Seq("Hello, world", "Goodbye, world")
    val datas = strings.map(Utils.stringToBinary)

    val key0 = DSA.genKeyPair(DSA.np, DSA.nq, 0)
    val sig0 = DSA.zeroMagicSignature

    datas.foreach{data =>
      assert(key0.toPub.validate(data, sig0))
    }

    val key1 = DSA.genKeyPair(DSA.np, DSA.nq, DSA.np + 1)
    val sig1 = DSA.oneMagicSignature(key1.toPub)

    datas.foreach{data =>
      assert(key1.toPub.validate(data, sig1))
    }
  }

  it("C46") {
    val text = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    val textVal = BigInt(1, Base64.decode(text).toArray)

    //val kp = RSA.genKeyPair(1024)
    val kp = RSA.genKeyPair(512) // Have tests run faster
    val enc = RSA.encrypt(textVal, kp)
    val isEven = RSA.isEven(_: BigInt, kp)
    val dec = RSA.isEvenAttack(enc, RSA.RSAPub(kp), isEven)
    assert(dec == textVal)
  }
}
