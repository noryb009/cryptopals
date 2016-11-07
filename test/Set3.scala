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
}
