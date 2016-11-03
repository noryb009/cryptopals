import org.scalatest.FunSpec

class Set2 extends FunSpec {
  it("C9") {
    val key = "YELLOW SUBMARINE"
    val expected = "YELLOW SUBMARINE\4\4\4\4"
    assert(AES.padPKCS7(key, 20) == expected)
  }

  it("C10") {
    val data = Base64.decodeFile("res/S2C10.txt")
    val key = "YELLOW SUBMARINE"
    val start = "I'm back and I'm ringin' the bell \n"
    val end = "Play that funky music \n"
    val decrypted = Utils.binaryToString(AES.unpadPKCS7(AES.decryptCBC(data, key)).get)
    assert(decrypted.startsWith(start))
    assert(decrypted.endsWith(end))
  }

  it("C11") {
    //for(a <- 1 to 200)
    assert(AES.checkOracle)
  }

  it("C12") {
    val str = Base64.decodeFile("res/S2C12.txt")
    assert(AES.checkDecryptSuffix(str))
  }

  it("C13") {
    assert(KeyVal.checkMakeAdmin)
  }

  it("C14") {
    val str = Base64.decodeFile("res/S2C12.txt")
    //for(a <- 1 to 200)
    assert(AES.checkDecryptSuffixWithPrefix(str))
  }

  it("C15") {
    def validSuffix(s: Seq[Byte]) =
      AES.unpadPKCS7(Utils.stringToBinary("ICE ICE BABY") ++ s).isDefined

    assert(validSuffix(Seq(4, 4, 4, 4)))
    assert(!validSuffix(Seq(5, 5, 5, 5)))
    assert(!validSuffix(Seq(1, 2, 3, 4)))
  }
}
