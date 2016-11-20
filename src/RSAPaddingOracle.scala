import RSA._

import scala.annotation.tailrec
import scala.util.Random

object RSAPaddingOracle {
  def checkPaddingOracle(kp: RSAKey, len: Int)(data: BigInt): Boolean = {
    val dec = kp.decrypt(data).toByteArray
    if(dec.head == 0)
      dec.length == (len / 8) && dec(1) == 2
    else
      dec.length == (len / 8) - 1 && dec.head == 2
  }

  case class M(a: BigInt, b: BigInt)

  def apply(oracle: BigInt => Boolean, c: BigInt, pub: RSAPub, k: Int): BigInt = {
    def rsamult(c: BigInt, s: BigInt) =
      c * s.modPow(pub.e, pub.n) % pub.n

    val B = BigInt(2).pow(k - 16)

    @tailrec
    def step1: (BigInt, BigInt) = {
      val s0 = BigInt(k, Random) % (pub.n - 1) + 1
      val c0 = rsamult(c, s0)
      if(oracle(c0))
        (s0, c0)
      else
        step1
    }

    val (s0, c0) = step1

    def ceilDiv(a: BigInt, b: BigInt) = {
      val (div, mod) = a /% b
      if(mod == 0)
        div
      else
        div + 1
    }

    val minS1 = ceilDiv(pub.n, 3 * B)
    @tailrec
    def step2ab(si: BigInt = minS1): BigInt = {
      val ci = rsamult(c0, si)
      if(oracle(ci))
        si
      else
        step2ab(si + 1)
    }

    def step2c(si1: BigInt, mi1: M): BigInt = {
      val M(a, b) = mi1
      val minR = ceilDiv(2 * (b * si1 - 2 * B), pub.n)

      @tailrec
      def inner(r: BigInt): BigInt = {
        def minS = ceilDiv(2 * B + r * pub.n, b)
        def maxS = ceilDiv(3 * B + r * pub.n, a)
        (minS until maxS).find(s => oracle(rsamult(c0, s))) match {
          case Some(s) => s
          case None => inner(r + 1)
        }
      }
      inner(minR)
    }

    def step2(ms: Seq[M], si1: Option[BigInt]): BigInt =
      (si1, ms.length) match {
        case (None, _) => step2ab()
        case (Some(s), 1) => step2c(s, ms.head)
        case (Some(s), _) => step2ab(s + 1)
      }

    def combineM(mLst: Seq[M]): Seq[M] =
      mLst.foldRight(Seq[M]()){
        case (m, n +: rst) if m.b >= n.a => M(Seq(m.a, n.a).min, n.b) +: rst
        case (m, rst) => m +: rst
      }

    def step3(mis1: Seq[M], si: BigInt): Seq[M] = {
      val misUnsorted = mis1.flatMap{mi1 =>
        val minr = ceilDiv(mi1.a * si - 3 * B + 1, pub.n)
        val maxr = (mi1.b * si - 2 * B) / pub.n

        (minr to maxr).flatMap{r =>
          val min = Seq(mi1.a, ceilDiv(2 * B + r * pub.n, si)).max
          val max = Seq(mi1.b, (3 * B - 1 + r * pub.n) / si).min
          if(min <= max) Some(M(min, max)) else None
        }
      }

      val mis = misUnsorted.sortBy(m => m.b)
      combineM(mis)
    }

    def step4(mi: Seq[M], si: BigInt): Option[BigInt] =
      mi match {
        case Seq(a) if a.a == a.b => Some(a.a * s0.modInverse(pub.n) % pub.n)
        case _ => None
      }

    @tailrec
    def inner(mi1: Seq[M], si1: Option[BigInt]): BigInt = {
      val si = step2(mi1, si1)
      val mi = step3(mi1, si)
      step4(mi, si) match {
        case None => inner(mi, Some(si))
        case Some(m) => m
      }
    }

    val m0 = M(2 * B, 3 * B - 1)
    inner(Seq(m0), None)
  }
}
