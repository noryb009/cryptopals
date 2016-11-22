import org.scalatest.FunSpec

import scala.util.Random

class Set7 extends FunSpec {
  it("C49 Part 1") {
    val attacker1 = Random.nextInt(Int.MaxValue) + 1
    val attacker2 = Random.nextInt(Int.MaxValue)
    val victim = Random.nextInt(attacker1) // Same or less digits
    val key = AES.randomString(16)
    val client = CBCMAC.Forge.clientReq(key, attacker1)_
    val msg = CBCMAC.Forge.forge(client, victim, attacker1, attacker2)
    val paramsOpt = CBCMAC.Forge.server(key, msg)
    assert(paramsOpt.isDefined)
    val params = paramsOpt.get
    assert(params("from").exists(_.toInt == victim))
    assert(params("to").contains(attacker2.toString))
    assert(params("amount").contains("1000000"))
  }

  it("C49 Part 2") {
    val attacker = Random.nextInt(Int.MaxValue)
    val victim = Random.nextInt(Int.MaxValue)
    val key = AES.randomString(16)

    val tx = Seq((Random.nextInt(Int.MaxValue), BigInt(Random.nextInt(Int.MaxValue))))
    val captured = CBCMAC.Forge.clientReqFixedIV(key, victim)(tx)

    val client = CBCMAC.Forge.clientReqFixedIV(key, attacker)_
    val msg = CBCMAC.Forge.forgeFixedIV(client, captured, attacker)
    val paramsOpt = CBCMAC.Forge.serverFixedIV(key, msg)
    assert(paramsOpt.isDefined)
    val params = paramsOpt.get
    assert(params("from").contains(victim.toString))
    assert(params("tx_list").get.split(";").contains(attacker.toString + ":1000000"))
  }

  it("C50") {
    val input = "alert('MZA who was that?');\n"
    val output = "alert('Ayo, the Wu is back!');//"
    val key = "YELLOW SUBMARINE"
    val hash = CBCMAC(Utils.stringToBinary(input), key, None)
    assert(Hex.encode(hash) == "296b8d7cb78a243dda4d0a61d33bbdd1")

    val fake = CBCMAC.fakeHash(input, output, key)
    assert(CBCMAC(fake, key, None) == hash)
    assert(fake.startsWith(output))
    assert(!fake.dropRight(1).contains('\n'.toByte))
    assert(!fake.contains('\r'.toByte))

    //println(Utils.binaryToString(fake))
  }
}
