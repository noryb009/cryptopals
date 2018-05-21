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

  it("C51") {
    val sessionID = Base64.encode(AES.randomBytes(32))
    //val sessionID = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
    val oracle = Crime.oracle(sessionID)_
    val oracleCBC = Crime.oracleCBC(sessionID)_
    def assertCorrect(cur: String): Unit = {
      assert(sessionID.startsWith(cur))
    }

    val result = Crime.attack(oracle, assertCorrect)
    assert(result == sessionID)
    val resultCBC = Crime.attack(oracleCBC, assertCorrect)
    assert(resultCBC == sessionID)
  }

  it("C52") {
    val (h1, h2) = Hash.Collision.doubleCollision.get
    assert(h1 != h2)
    assert(Hash.Collision.doubleHash(h1) == Hash.Collision.doubleHash(h2))
  }

  it("C53") {
    val k = 8
    val M = AES.randomBytes(Math.pow(2, k).toInt)
    val hi = Hash.Collision.hi1
    val M2 = Hash.Collision.expandable(M, hi).get
    assert(M != M2)
    assert(M.length == M2.length)
    assert(Hash.Collision.badMD(M, hi) == Hash.Collision.badMD(M2, hi))
  }

  it("C54") {
    val k = 4
    val len = 20
    val hi = Hash.Collision.hi1
    val (h, m2Len, info) = Hash.Collision.predictPart1(k, len, hi).get
    val m = AES.randomBytes(len)
    val m2 = Hash.Collision.predictPart2(m, info, hi).get
    assert(m2.startsWith(m))
    assert(Hash.Collision.badMD(m2, hi) == h)
    assert(m2.length == m2Len)
  }

  // This can take a while. For the example below, it took >500000 iterations.
  ignore("C55") {
    // Example collision:
    // 16043f1b135b012fcecd0ec7027ecb7664fd75dab96f5ee9b075884d2b749e28e63f774b7467d9a604f11029fb73b5aa6b40cbb357407205c6570c042aaa5d91
    // 16043f1b135b01afcecd0e37027ecb7664fd75dab96f5ee9b075884d2b749e28e63f774b7467d9a604f11029fb73b5aa6b40cab357407205c6570c042aaa5d91

    val iterations = 10000000
    //val iterations = 1
    val v = (0 to iterations).collectFirst(Function.unlift{i =>
      if (i % 100000 == 0) {
        println(i)
      }
      Hash.MD4.collideMD4
    })

    // There's a chance this will be falsely asserted, since generating a
    // collision isn't guaranteed.
    assert(v.isDefined)

    val (m, mPrime) = v.get
    assert(m != mPrime)
    assert(Hash.md4(m) == Hash.md4(mPrime))
    println(Hex.encode(m))
    println(Hex.encode(mPrime))
  }

  // This is super slow (>10 minutes), and there's a small chance it fails.
  ignore("C56") {
    val cookie = "QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F"
    val data = Base64.decode(cookie)
    val oracle = RC4.encryptOracle(data) _
    val result = RC4.byteBias(oracle)

    assert(result.length == data.length)

    // Adding more iterations could improve the accuracy (to ~100%), but that would take a long time.
    // Currently, ~2/3 of the characters are correctly guessed.
    val correct = result.zip(data).count{case (a, b) => a == b}
    val incorrect = result.length - correct
    assert(correct >= incorrect)
    println(Utils.binaryToString(data))
    println(Utils.binaryToString(result))
  }
}
