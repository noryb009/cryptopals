import org.scalatest.FunSpec

class Set2 extends FunSpec {
  it("C1") {
    val key = "YELLOW SUBMARINE"
    val expected = "YELLOW SUBMARINE\4\4\4\4"
    assert(AES.PKCS7(key, 20) == expected)
  }
}
