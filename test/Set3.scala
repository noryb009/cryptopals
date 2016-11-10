import org.scalatest.FunSpec

import scala.util.Random

class Set3 extends FunSpec {
  val c17Data = Seq(
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
  )

  it("C17") {
    def randomContentEnc(con: String, key: String): Seq[Byte] =
      AES.encryptCBC(AES.padPKCS7(Base64.decode(con), 16), key)

    c17Data.foreach(str => {
      val key = AES.randomString(16)
      val enc = randomContentEnc(str, key)
      val decryptor = (data: Seq[Byte], iv: Seq[Byte]) => CBCPaddingOracle.validContent(data, key, iv)
      val dec = CBCPaddingOracle.cbcPaddingOracle(enc, decryptor).get
      assert(dec == Utils.binaryToString(Base64.decode(str)))
    })
  }

  it("C18") {
    val data = Base64.decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    val key = "YELLOW SUBMARINE"
    val expected = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    assert(Utils.binaryToString(AES.decryptCTR(data, AES.genKeyStream(key))) == expected)

    val rand = AES.randomBytes(40)
    val key2 = AES.randomString(16)
    assert(AES.decryptCTR(AES.encryptCTR(rand, AES.genKeyStream(key2)), AES.genKeyStream(key2)) == rand)
  }

  /* TODO:
   * These challenges, 19 and 20, could use a bit of work, mostly in the
   * English-processing components.
   */

  def c19c20Helper(file: String): String = {
    val data = Base64.decodeLines(file)
    val key = AES.randomString(16)
    val keyStream = AES.genKeyStream(key)
    val encs = data.map(AES.encryptCTR(_, keyStream))
    val minLen = encs.map(_.length).min
    val total = encs.map(_.take(minLen)).reduceLeft[Seq[Byte]]{_ ++ _}
    Utils.binaryToString(XOR.decryptKnownKeySize(total, minLen).get)
  }

  it("C19") {
    val start = "i have met them at c"
    assert(c19c20Helper("res/S3C19.txt").startsWith(start))
  }

  it("C20") {
    val start = "I'm rated \"R\"...this is a warning, ya better void / P"
    assert(c19c20Helper("res/S3C20.txt").startsWith(start))
  }

  it("C21") {
    val mt = MersenneTwister.createStream(5)
    assert(mt.head == 953453411)
  }

  it("C22") {
    val seed = MersenneTwister.getTime
    val mt = MersenneTwister.createStream(seed)
    val num = mt.head
    //val sleepTime = Math.abs(num) % 960 + 40
    val sleepTime = Math.abs(num) % 5
    Thread.sleep(sleepTime * 1000)
    assert(MersenneTwister.getSeedFromOutput(num).get == seed)
  }

  it("C23") {
    val mt = MersenneTwister.createStream(Random.nextInt)
    val mt2 = MersenneTwister.cloneStream(mt)
    assert(mt.take(MersenneTwister.N*2) == mt2.take(MersenneTwister.N*2))
  }

  it("C24") {
    def testSeed(range: Range, seed: Int): Boolean = {
      val mt = MersenneTwister.createStream(seed)
      val encryptor = (s: Seq[Byte]) => MersenneTwister.encryptUsingMT(AES.randomBytes(Random.nextInt(20)) ++ s, mt)
      val seeds = MersenneTwister.getSeedFromEncrypted(encryptor, range)
      seeds.contains(seed)
    }

    //val pow = Math.pow(2, 16).toInt
    val pow = Math.pow(2, 8).toInt
    assert(testSeed(0 until pow, Random.nextInt(pow)))
    val time = MersenneTwister.getTime
    //val diff = 500
    val diff = 50
    assert(testSeed((time - diff) to (time + diff), time))
  }
}
