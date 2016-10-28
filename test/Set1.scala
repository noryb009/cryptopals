import org.scalatest.FunSpec

class Set1 extends FunSpec {
  it("C1") {
    val str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    val expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert(Base64.encode(Hex.decode(str)) == expected)
  }

  it("C2") {
    val a = "1c0111001f010100061a024b53535009181c"
    val b = "686974207468652062756c6c277320657965"
    val expected = "746865206b696420646f6e277420706c6179"
    assert(Hex.encode(XOR.xor(Hex.decode(a), Hex.decode(b))) == expected)
  }

  it("C3") {
    val str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    val expected = "Cooking MC's like a pound of bacon"
    assert(Utils.binaryToString(XOR.singleByte(Hex.decode(str))) == expected)
  }
}
