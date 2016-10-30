import org.scalatest.FunSpec

class Set1 extends FunSpec {
  it("C1") {
    val s = "61626364656667"
    assert(Base64.decode(Base64.encode(Hex.decode(s))) == Hex.decode(s))
    val str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    val expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert(Base64.encode(Hex.decode(str)) == expected)
  }

  it("C2") {
    val a = "1c0111001f010100061a024b53535009181c"
    val b = "686974207468652062756c6c277320657965"
    val expected = "746865206b696420646f6e277420706c6179"
    assert(Hex.encode(XOR.xor(Hex.decode(a), Hex.decode(b).toIndexedSeq)) == expected)
  }

  it("C3") {
    val str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    val expected = "Cooking MC's like a pound of bacon"
    assert(Utils.binaryToString(XOR.singleByte(Hex.decode(str)).get) == expected)
  }

  it("C4") {
    val strs = Hex.decodeLines("res/S1C4.txt")
    val expected = "Now that the party is jumping\n"
    assert(Utils.binaryToString(XOR.decryptOneOf(strs)) == expected)
  }

  it("C5") {
    val str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    val key = "ICE"
    val expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" +
      "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    assert(Hex.encode(XOR.xor(Utils.stringToBinary(str), Utils.stringToBinary(key).toIndexedSeq)) == expected)
  }

  it("C6") {
    val str = Base64.decodeFile("res/S1C6.txt")
    val start = "I'm back and I'm ringin' the bell \n"
    val end = "Play that funky music \n"
    val decrypted = Utils.binaryToString(XOR.decryptUnknownKeySize(str).get)
    assert(decrypted.startsWith(start))
    assert(decrypted.endsWith(end))
  }

  it("C7") {
    val data = Base64.decodeFile("res/S1C7.txt")
    val key = "YELLOW SUBMARINE"
    val start = "I'm back and I'm ringin' the bell \n"
    assert(Utils.binaryToString(AES.decrypt(data, key)).startsWith(start))
  }

  it("C8") {
    val strs = Hex.decodeLines("res/S1C8.txt")
    assert(strs.view.exists(AES.isECB))
  }
}
