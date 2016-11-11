import org.scalatest.FunSpec

class Set4 extends FunSpec {
  it("C25") {
    def getPlaintext: Seq[Byte] = {
      val data = Base64.decodeFile("res/S4C25.txt")
      val key = "YELLOW SUBMARINE"
      AES.decrypt(data, key)
    }

    val key = AES.genKeyStream(AES.randomString(16))
    val enc = AES.encryptCTR(Seq[Byte](1, 2, 3, 4), key)
    val edited = AES.editCTR(enc, key, 1, Seq[Byte](4, 5))
    assert(AES.decryptCTR(edited, key) == Seq[Byte](1, 4, 5, 4))

    val data = getPlaintext
    val encData = AES.encryptCTR(data, key)
    val editor = (offset: Int, newText: Seq[Byte]) => AES.editCTR(encData, key, offset, newText)

    assert(AES.attackEditCTR(encData, editor) == data)
  }
}
