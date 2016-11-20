import org.scalatest.FunSpec

import scala.util.Random

class Set7 extends FunSpec {
  it("C49 With IV") {
    val attacker1 = Random.nextInt(Int.MaxValue) + 1
    val attacker2 = Random.nextInt(Int.MaxValue)
    val victim = Random.nextInt(attacker1) // Same or less digits
    val key = AES.randomString(16)
    val client = CBCMAC.Forge.clientReq(key, attacker1)_
    val msg = CBCMAC.Forge.forge(client, victim, attacker1, attacker2)
    val paramsOpt = CBCMAC.Forge.server(key, msg)
    assert(paramsOpt.isDefined)
    val params = paramsOpt.get
    assert(params("from").contains(victim.toString))
    assert(params("to").contains(attacker2.toString))
    assert(params("amount").contains("1000000"))
  }
}
