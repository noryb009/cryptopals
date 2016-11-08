import scala.annotation.tailrec

object MersenneTwister {
  val N = 624
  val M = 397
  val R = 31
  val A = 0x9908B0DF

  val F = 1812433253

  val U = 11
  val D = 0xFFFFFFFF

  val S = 7
  val B = 0x9D2C5680

  val T = 15
  val C = 0xEFC60000

  val L = 18

  val MASK_LOWER = (1 << R) - 1
  val MASK_UPPER = 1 << R

  case class MT(mt: IndexedSeq[Int], index: Int) {
    def twist: IndexedSeq[Int] = {
      def twistWith(
                     start: Int, end: Int,
                     mtUpOne: IndexedSeq[Int], mtUpM: IndexedSeq[Int],
                     oneOffset: Int, mOffset: Int
                   ): IndexedSeq[Int] = {
        (0 until end - start).map {i =>
          val upOne = mtUpOne((i + oneOffset + N) % N)
          val upM: Int = mtUpM((i + mOffset + N) % N)

          val x = (mt(i + start) & MASK_UPPER) + (upOne & MASK_LOWER)
          val xAPrime = x >>> 1
          val xA = if ((x & 0x1) == 0) xAPrime else xAPrime ^ A
          upM ^ xA
        }
      }

      /*
       * Note that some numbers rely on other numbers, namely (i + 1) and (i + M).
       * Some of these are from the old array, while others are from the new array.
       * Instead of mutation, we split this into "blocks". These feed into each other,
       * when required. Note that nothing in each block depend on each other, so they
       * could be parallelized.
       */

      val split1 = 227
      val split2 = 454
      val split3 = 623

      val mt1 = twistWith(0, split1, mt, mt, 1, M)
      val mt2 = twistWith(split1, split2, mt, mt1, split1 + 1, 0)
      val mt3 = twistWith(split2, split3, mt, mt2, split2 + 1, 0)
      val mt4 = twistWith(split3, N, mt1, mt2, split3 + 1, split3 - split2)

      mt1 ++ mt2 ++ mt3 ++ mt4
    }

    @tailrec
    final def nextInt: (Int, MT) = {
      if(index >= N) {
        MT(twist, 0).nextInt
      } else {
        val i = index % N

        val y1 = mt(i)
        val y2 = y1 ^ (mt(i) >>> U)
        val y3 = y2 ^ (y2 << S) & B
        val y4 = y3 ^ (y3 << T) & C
        val y5 = y4 ^ (y4 >>> L)

        (y5, MT(mt, i + 1))
      }
    }
  }

  def createMT(seed: Int): MT = {
    val mt = (0 until N).foldLeft(List[Int]()){
      case (acc, 0) => List(seed)
      case (acc, i) => (F * (acc.head ^ (acc.head >>> 30)) + i) +: acc
    }.reverse.toIndexedSeq

    MT(mt, N)
  }

  def createStream(seed: Int): Stream[Int] = {
    def loop(mt: MT): Stream[Int] = {
      val (i, mt2) = mt.nextInt
      i #:: loop(mt2)
    }

    loop(createMT(seed))
  }
}
