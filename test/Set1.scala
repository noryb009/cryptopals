import org.scalatest.FunSpec

class Set1 extends FunSpec {
  it("C1") {
    val str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    val expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert(Base64.encode(Hex.decode(str)) == expected)
  }
}
