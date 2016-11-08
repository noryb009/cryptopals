import org.scalatest.FunSpec

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

  it("C21") {
    val mt = MersenneTwister.createStream(5)
    assert(mt.head == 953453411)
  }
}
