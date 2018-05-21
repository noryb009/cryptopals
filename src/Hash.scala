import scala.annotation.tailrec

object Hash {
  // Int is 32 bits
  def intTo32Bit(n: Int): Seq[Byte] = {
    def getByte(c: Int): Byte = ((n >>> (c * 8)) & 0xFF).toByte
    Seq.tabulate[Byte](4)(getByte).reverse
  }

  def intTo64Bit(n: Int): Seq[Byte] =
    Seq.fill[Byte](4)(0) ++ intTo32Bit(n)

  def bitsToInt(s: Seq[Byte]): Int =
    s.reverse.zipWithIndex.map { case (n, i) => (n << (8 * i)) & (0xFF << (8 * i)) }.sum

  def rotl(x: Int, n: Int): Int =
    (x >>> (32 - n)) | (x << n)
  def rotr(x: Int, n: Int): Int = rotl(x, 32 - n)

  def sha1Padding(dataLength: Int): Seq[Byte] = {
    val padLen = ((64 + 56) - ((dataLength + 1) % 64)) % 64
    0x80.toByte +: (Seq.fill[Byte](padLen)(0) ++ intTo64Bit(dataLength * 8))
  }

  def md4Padding(dataLength: Int): Seq[Byte] = {
    val padding = sha1Padding(dataLength)
    val (zeros, len) = padding.splitAt(padding.length - 8)
    zeros ++ len.reverse
  }

  def sha1CalcChunk(chunk: Seq[Byte], h: Seq[Int]): Seq[Int] = {
    val a = 0
    val b = 1
    val c = 2
    val d = 3
    val e = 4

    val w = chunk.grouped(4).map(bitsToInt).toIndexedSeq

    @tailrec
    def extend(w: IndexedSeq[Int]): IndexedSeq[Int] =
      if (w.length == 80)
        w
      else
        extend(rotl(w(2) ^ w(7) ^ w(13) ^ w(15), 1) +: w)

    val w2 = extend(w.reverse).reverse

    val letters = w2.zipWithIndex.foldLeft(h) { case (h, (w, i)) => {
      val (f, k) =
        if (i <= 19)
          ((h(b) & h(c)) | (~h(b) & h(d)), 0x5A827999)
        else if (i <= 39)
          (h(b) ^ h(c) ^ h(d), 0x6ED9EBA1)
        else if (i <= 59)
          ((h(b) & h(c)) | (h(b) & h(d)) | (h(c) & h(d)), 0x8F1BBCDC)
        else
          (h(b) ^ h(c) ^ h(d), 0xCA62C1D6)
      Seq(
        rotl(h(a), 5) + f + h(e) + k + w,
        h(a),
        rotl(h(b), 30),
        h(c),
        h(d)
      )
    }
    }
    h.zip(letters).map { case (x, y) => x + y }
  }

  def sha1FromH(data: Seq[Byte], h: Seq[Int]): Seq[Byte] =
    data
      .grouped(64)
      .foldLeft(h){case (hVal, chunk) => sha1CalcChunk(chunk, hVal)}
      .flatMap(intTo32Bit)

  def sha1(data: Seq[Byte]): Seq[Byte] = {
    val h = Seq(
      0x67452301,
      0xEFCDAB89,
      0x98BADCFE,
      0x10325476,
      0xC3D2E1F0
    )

    val padding = sha1Padding(data.length)
    sha1FromH(data ++ padding, h)
  }

  def sha1HMAC(message: Seq[Byte], key: String): Seq[Byte] =
    sha1(Utils.stringToBinary(key) ++ message)

  def sha1HMACCheck(message: Seq[Byte], key: String, sha: Seq[Byte]): Boolean =
    sha1HMAC(message, key) == sha

  def appendSha1(sha: Seq[Byte], suffix: Seq[Byte], origSize: Int): Seq[Byte] = {
    val h = sha
      .grouped(4)
      .map(bitsToInt)
      .toSeq
    val padding = sha1Padding(origSize + sha1Padding(origSize).length + suffix.length)
    sha1FromH(suffix ++ padding, h)
  }

  object MD4 {
    val Q = Seq(
      0x67452301,
      0xefcdab89,
      0x98badcfe,
      0x10325476
    )
    val QMixed = Seq(
      0xefcdab89,
      0x98badcfe,
      0x10325476,
      0x67452301
    )

    val k = Seq(
      0x00000000,
      0x5a827999,
      0x6ed9eba1
    )

    val shift = Seq(
      Seq(3, 7, 11, 19),
      Seq(3, 5, 9, 13),
      Seq(3, 9, 11, 15)
    )

    val a = 0
    val b = 1
    val c = 2
    val d = 3

    def F(a: Int, b: Int, c: Int): Int = (a & b) | (~a & c)
    def G(a: Int, b: Int, c: Int): Int = (a & b) | (a & c) | (b & c)
    def H(a: Int, b: Int, c: Int): Int = a ^ b ^ c

    val xInd1 = IndexedSeq(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
    val xInd2 = IndexedSeq(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    val xInd3 = IndexedSeq(0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
    val xInds = xInd1 ++ xInd2 ++ xInd3

    def md4CalcChunk(chunk: Seq[Byte], Q: Seq[Int]): Seq[Int] = {
      val X = chunk
        .grouped(4)
        .map(x => bitsToInt(x.reverse))
        .toIndexedSeq

      val letters1 = (0 until 16).foldLeft(Q){case (q, i) => {
        Seq(
          q(d),
          rotl(q(a) + F(q(b), q(c), q(d)) + X(i) + k.head, shift.head(i % 4)),
          q(b),
          q(c)
        )
      }}

      val letters2 = (0 until 16).foldLeft(letters1){case (q, i) =>
        Seq(
          q(d),
          rotl(q(a) + G(q(b), q(c), q(d)) + X(xInd2(i)) + k(1), shift(1)(i % 4)),
          q(b),
          q(c)
        )
      }

      val letters3 = (0 until 16).foldLeft(letters2){case (q, i) =>
        Seq(
          q(d),
          rotl(q(a) + H(q(b), q(c), q(d)) + X(xInd3(i)) + k(2), shift(2)(i % 4)),
          q(b),
          q(c)
        )
      }

      Q.zip(letters3).map{case (x, y) => x + y}
    }

    def md4FromQ(data: Seq[Byte], Q: Seq[Int]): Seq[Byte] =
      data
        .grouped(64)
        .foldLeft(Q){case (qVal, chunk) => md4CalcChunk(chunk, qVal)}
        .flatMap(x => intTo32Bit(x).reverse)

    def md4(data: Seq[Byte]): Seq[Byte] = {
      val padding = md4Padding(data.length)
      md4FromQ(data ++ padding, MD4.Q)
    }

    type ConditionSide = Either[(Int, Int, Boolean), Int]
    case class CollisionCondition(L: Int, R: ConditionSide)

    val collisionSteps = {
      def letterMsgToStep(l: Int, msg: Int): Int = {
        val letterVal =
          if(l == a) 1
          else if(l == d) 2
          else if(l == c) 3
          else 4
        (msg - 1) * 4 + letterVal
      }
      // Two bits equal each other (or are unequal).
      def ccR(bitL: Int, letterR: Int, msgR: Int, bitR: Int, inv: Boolean = false): CollisionCondition =
        CollisionCondition(bitL, Left(letterMsgToStep(letterR, msgR), bitR, inv))
      // A bit equals a certain value.
      def cc(bitL: Int, value: Int): CollisionCondition =
        CollisionCondition(bitL, Right(value))
      case class CollisionStep(step: Int, ccs: Seq[CollisionCondition])
      def cs(letter: Int, msg: Int, ccs: CollisionCondition*): CollisionStep =
        CollisionStep(letterMsgToStep(letter, msg), ccs)
      val not = true
      // These are directly from table 6 of the paper "Cryptanalsis of the Hash Functions MD4 and RIPEMD" by Wang, Lai,
      // Feng, Chen and Yu.
      // Two extra conditions are from "Improved Collision Attack on MD4" by Naito, Sasaki, Kunihiro, and Ohta.
      val csSeq = Seq(
        cs(a, 1, ccR(7, b, 0, 7)),
        cs(d, 1, cc(7, 0), ccR(8, a, 1, 8), ccR(11, a, 1, 11)),
        cs(c, 1, cc(7, 1), cc(8, 1), cc(11, 0), ccR(26, d, 1, 26)),
        cs(b, 1, cc(7, 1), cc(8, 0), cc(11, 0), cc(26, 0)),
        cs(a, 2, cc(8, 1), cc(11, 1), cc(26, 0), ccR(14, b, 1, 14)),
        cs(d, 2, cc(14, 0), ccR(19, a, 2, 19), ccR(20, a, 2, 20), ccR(21, a, 2, 21), ccR(22, a, 2, 22), cc(26, 1)),
        cs(c, 2, ccR(13, d, 2, 13), cc(14, 0), ccR(15, d, 2, 15), cc(19, 0), cc(20, 0), cc(21, 1), cc(22, 0)),
        cs(b, 2, cc(13, 1), cc(14, 1), cc(15, 0), ccR(17, c, 2, 17), cc(19, 0), cc(20, 0), cc(21, 0), cc(22, 0)),
        cs(a, 3, cc(13, 1), cc(14, 1), cc(15, 1), cc(17, 0), cc(19, 0), cc(20, 0), cc(21, 0), ccR(23, b, 2, 23), cc(22, 1), ccR(26, b, 2, 26)),
        cs(d, 3, cc(13, 1), cc(14, 1), cc(15, 1), cc(17, 0), cc(20, 0), cc(21, 1), cc(22, 1), cc(23, 0), cc(26, 1), ccR(30, a, 3, 30)),
        cs(c, 3, cc(17, 1), cc(20, 0), cc(21, 0), cc(22, 0), cc(23, 0), cc(26, 0), cc(30, 1), ccR(32, d, 3, 32)),
        cs(b, 3, cc(20, 0), cc(21, 1), cc(22, 1), ccR(23, c, 3, 23), cc(26, 1), cc(30, 0), cc(32, 0)),
        cs(a, 4, cc(23, 0), cc(26, 0), ccR(27, b, 3, 27), ccR(29, b, 3, 29), cc(30, 1), cc(32, 0)),
        cs(d, 4, cc(23, 0), cc(26, 0), cc(27, 1), cc(29, 1), cc(30, 0), cc(32, 1)),
        cs(c, 4, ccR(19, d, 4, 19), cc(23, 1), cc(26, 1), cc(27, 0), cc(29, 0), cc(30, 0)),
        cs(b, 4, cc(19, 0), cc(26, 1), cc(27, 1), cc(29, 1), /*cc(30, 0),*/ ccR(32, c, 4, 32)),
        cs(a, 5, ccR(19, c, 4, 19), cc(26, 1), cc(27, 0), cc(29, 1), cc(32, 1)),
        cs(d, 5, /*ccR(19, a, 5, 19), ccR(26, b, 4, 26), ccR(27, b, 4, 27),*/ ccR(29, b, 4, 29), ccR(32, b, 4, 32)),
        cs(c, 5, ccR(26, d, 5, 26), ccR(27, d, 5, 27), ccR(29, d, 5, 29), ccR(30, d, 5, 30), ccR(32, d, 5, 32)),
        cs(b, 5, ccR(29, c, 5, 29), cc(30, 1), cc(32, 0)),
        cs(a, 6, cc(29, 1), /*cc(30, 0),*/ cc(32, 1)),
        cs(d, 6, ccR(29, b, 5, 29)),
        cs(c, 6, ccR(29, d, 6, 29), ccR(30, d, 6, 30, not), ccR(32, d, 6, 32, not)),
        cs(b, 9, cc(32, 1)),
        cs(a, 10, cc(32, 1))
      )
      csSeq.foldLeft(Map[Int, Seq[CollisionCondition]]()){case (map, cs) => map + (cs.step -> cs.ccs)}
    }

    def collideMD4: Option[(Seq[Byte], Seq[Byte])] = {
      /* Q is a stack of states. It initially contains (B[0], C[0], D[0], A[0]).
       * If a state is added, it adds one to the top. This then becomes
       * (B[1], B[0], C[0], D[0], A[0]), also known as (B[1], C[1], D[1], A[1], A[0]).
       * So if Q.length = i, B[i] is always at the top of the stack, C[i] is second, etc.
       */
      case class MD4History(Q: List[Int], X: IndexedSeq[Int]) {
        val num: Int = Q.length - 4
        val a: Int = Q(3)
        val b: Int = Q.head
        val c: Int = Q(1)
        val d: Int = Q(2)
        def aP: Int = Q(4)
        def bP: Int = Q(1)
        def cP: Int = Q(2)
        def dP: Int = Q(3)

        def getNextMD4Item: Int = {
          if(num < 16) {
            rotl(a + F(b, c, d) + X(num) + k.head, shift.head(num % 4))
          } else if(num < 32) {
            rotl(a + G(b, c, d) + X(xInd2(num - 16)) + k(1), shift(1)(num % 4))
          } else {
            rotl(a + H(b, c, d) + X(xInd3(num - 32)) + k(2), shift(2)(num % 4))
          }
        }

        /* This makes a MD4History that corresponds to the next step of the
         * regular MD4 algorithm.
         */
        def next: MD4History = {
          val v = getNextMD4Item
          MD4History(v +: Q, X)
        }

        def mask(bit: Int): Int = 1 << (bit - 1) // Bits in the table are 1-based.
        def getBit(n: Int, bit: Int): Int = (n & mask(bit)) >>> (bit - 1)

        def check: MD4History = {
          collisionSteps.get(num) match {
            case None =>
            case Some(steps) =>
              val curB = Q.head
              steps.foreach{
                case CollisionCondition(bitL, Left((stepR, bitR, target))) =>
                  assert((getBit(curB, bitL) == getBit(Q(num - stepR), bitR)) != target,
                    "Failed assert on round " + num)
                case CollisionCondition(bitL, Right(value)) =>
                  assert((getBit(curB, bitL) ^ value) != 1,
                    "Failed assert on round " + num)
              }
          }
          this
        }

        /* This first determines what we want the latest state to be (applying
         * properties from Table 6 in Wang's paper as necessary), then calls
         * fixInner.
         */
        def fix: MD4History = {
          collisionSteps.get(num) match {
            case None => this
            case Some(steps) => {
              val newB =
                steps.foldLeft(Q.head){case (curB, CollisionCondition(bitL, side)) =>
                  side match {
                    case Left((stepR, bitR, target)) =>
                      if((getBit(curB, bitL) == getBit(Q(num - stepR), bitR)) == target)
                        curB ^ mask(bitL)
                      else curB
                    case Right(value) =>
                      // If one is false, we need to flip the bit.
                      if((getBit(curB, bitL) ^ value) == 1)
                        curB ^ mask(bitL)
                      else curB
                  }
                }

              val newQ = newB +: Q.tail
              MD4History(newQ, X).fixInner
            }
          }
        }

        /* Given an inconsistent state, with a Q that works well for creating
         * collisions but an X that does not create the latest state, this
         * function modifies X so that it does create the latest state in Q.
         */
        def fixInner: MD4History = {
          // Note: We just updated newB, which was generated using
          // X[something], aP, bP, cP and dP.
          val newB = b
          val prevStep = num - 1
          val prevStepRound = prevStep / 16
          // We always need to recreate the message used in the previous step.
          val mixFn: (Int, Int, Int) => Int =
            prevStepRound match {
              case 0 => F
              case 1 => G
            }
          val newMessageItem =
            rotr(newB, shift(prevStepRound)(prevStep % 4)) - aP - mixFn(bP, cP, dP) - k(prevStepRound)
          val newX = X.patch(xInds(prevStep), Seq(newMessageItem), 1)
          if(prevStep < 16) {
            // We used X[prevStep]. Since this hasn't been used yet in the
            // algorithm, so it doesn't matter that we changed it.
            MD4History(Q, newX)
          } else if(prevStep < 32) {
            // X[xInds(prevStep)] was used to generate Qrev[4 + xInds(prevStep)]
            // (the 4 is from the initial 4 states).
            // In turn, this was used to calculate Qrev[4 + xInds(prevStep) + i],
            // for i = 1 to 4. We don't want to change these 4 states, so we
            // want to patch up the 4 messages used to generate them.
            // First, we want to get the new Qrev[4 + xInds(prevStep)].
            // Instead of reversing Q, we can calculate this.
            val extra = Q.length - 4 - xInds(prevStep)
            val newQState = MD4History(Q.drop(extra), newX).getNextMD4Item
            val newQ = Q.patch(extra - 1, Seq(newQState), 1)
            val newQIndexed = newQ.toIndexedSeq
            // Calculate new messages.
            val vFollowing = Seq.tabulate(4){n =>
              val step = xInds(prevStep) + 1 + n
              val qStart = extra - 2 - n
              val newBB = newQIndexed(qStart)
              val bb = newQIndexed(qStart + 1)
              val cc = newQIndexed(qStart + 2)
              val dd = newQIndexed(qStart + 3)
              val aa = newQIndexed(qStart + 4)
              rotr(newBB, shift.head(step % 4)) - aa - F(bb, cc, dd) - k.head
            }

            val newX2 = newX.patch(xInds(prevStep) + 1, vFollowing, 4)
            MD4History(newQ, newX2)
          } else {
            ???
          }
        }

        def nextN(n: Int): MD4History = {
          (0 until n).foldLeft(this){case (h, _) => h.next}
        }

        def nextFixN(n: Int): MD4History = {
          (0 until n).foldLeft(this){case (h, _) => h.next.fix}
        }

        def nextCheckN(n: Int): MD4History = {
          (0 until n).foldLeft(this){case (h, _) => h.next.check}
        }
      }

      def xToM(X: Seq[Int]): Seq[Byte] =
        X.flatMap(x => intTo32Bit(x))
      def mToX(m: Seq[Byte]): IndexedSeq[Int] =
        m
          .grouped(4)
          .map(x => bitsToInt(x))
          .toIndexedSeq

      val M = AES.randomBytes(64)

      // Some collisions to test with.
      val XA = IndexedSeq(
        0x4d7a9c83, 0x56cb927a, 0xb9d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f,
        0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dd8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9
        /*0x839c7a4d, 0x7a92cb56, 0x78a5d5b9, 0xeea5a757, 0x3c8a74de, 0xb366c3dc, 0x20a083b6, 0x9f5d2a3b,
        0xb3719dc6, 0x9891e9f9, 0x5e809fd7, 0xe8b23ba6, 0x318edd45, 0xe51fe397, 0x08bf9427, 0xe9c3e8b9*/
      )
      val XB = IndexedSeq(
        0x4d7a9c83, 0xd6cb927a, 0x29d5a578, 0x57a7a5ee, 0xde748a3c, 0xdcc366b3, 0xb683a020, 0x3b2a5d9f,
        0xc69d71b3, 0xf9e99198, 0xd79f805e, 0xa63bb2e8, 0x45dc8e31, 0x97e31fe5, 0x2794bf08, 0xb9e8c3e9
        /*0x839c7a4d, 0x7a92cbd6, 0x78a5d529, 0xeea5a757, 0x3c8a74de, 0xb366c3dc, 0x20a083b6, 0x9f5d2a3b,
        0xb3719dc6, 0x9891e9f9, 0x5e809fd7, 0xe8b23ba6, 0x318edc45, 0xe51fe397, 0x08bf9427, 0xe9c3e8b9*/
      )

      val X = mToX(M)
      //val X = XA

      val history = MD4History(QMixed.toList, X)
      val history2 = history
        // Fix first round constraints.
        .nextFixN(16)
        // Fix a5. This updates m[0] - m[4].
        .nextFixN(1)
        // Fix d5. This updates m[4] - m[8].
        .nextFixN(1)
      // Fixing any more clobbers first round constraints.
      //assert(history2.X == X)

      def addModifier(X: Seq[Int], pos: Int, delta: Int): Seq[Int] = {
        X.patch(pos, Seq(X(pos) + delta), 1)
      }
      // Add modifiers that are used for the collision differential.
      // Each item corresponds to a value. For example, (1, 1 << 31) => \delta m_1 = 2^{31}.
      // These are 0-indexed.
      val newM = xToM(history2.X)
      val mPrimeX =
        Seq((1, 1 << 31), (2, 1 << 31), (2, -(1 << 28)), (12, -(1 << 16)))
          .foldLeft[Seq[Int]](history2.X){case (acc, (nbInt, delta)) => addModifier(acc, nbInt, delta)}
      val mPrime = xToM(mPrimeX)

      // Note: The 18th iteration constraints (the first 3, specifically)
      // sometimes clobber first round constraints. But this happens <50%
      // of the time, so including them is worth it.
      val check = false
      if (check) {
        MD4History(QMixed.toList, history2.X)
          .nextCheckN(18)
      }

      val newM2 = newM.grouped(4).flatMap(_.reverse).toSeq
      val mPrime2 = mPrime.grouped(4).flatMap(_.reverse).toSeq

      if (md4(newM2) == md4(mPrime2))
        Some((newM2, mPrime2))
      else
        None
    }
  }

  val md4FromQ = MD4.md4FromQ _
  val md4 = MD4.md4 _

  def md4HMAC(message: Seq[Byte], key: String): Seq[Byte] =
    md4(Utils.stringToBinary(key) ++ message)

  def md4HMACCheck(message: Seq[Byte], key: String, hmac: Seq[Byte]): Boolean =
    md4HMAC(message, key) == hmac

  def appendMD4(hmac: Seq[Byte], suffix: Seq[Byte], origSize: Int): Seq[Byte] = {
    val Q = hmac
      .grouped(4)
      .map(x => bitsToInt(x.reverse))
      .toSeq
    val padding = md4Padding(origSize + sha1Padding(origSize).length + suffix.length)
    md4FromQ(suffix ++ padding, Q)
  }

  object Collision {
    case class HashInfo(key: String, h: Seq[Byte]) {
      val blockLen = h.length
    }
    val hi1 = HashInfo("YELLOW SUBMARINE", Seq[Byte](4, 4))
    val hi2 = HashInfo("SUBMARINE YELLOW", Seq[Byte](5, 5))

    def incSeq(cur: Seq[Byte]): Option[Seq[Byte]] = {
      val (overflowOuter, incOuter) = cur.foldRight(1, Seq[Byte]()){case (c, (overflow, inc)) =>
        val v = c.toInt + overflow
        ((v / Byte.MaxValue).toByte, v.toByte +: inc)
      }
      if(overflowOuter == 1) None
      else Some(incOuter)
    }

    // Padding is easy to deal with, as every input is a length divisible by the padding length.
    // This lets us generate strings that collide, then add the same padding to each, keeping the
    // colliding property.
    def badMDNoPad(data: Seq[Byte], init: Seq[Byte], key: String): Seq[Byte] =
      data
        .grouped(init.length)
        .foldLeft(init){(h, cur) => AES.encrypt(AES.padPKCS7(h ++ cur), key).take(h.length)}
    def badMDNoPad(data: Seq[Byte], hi: HashInfo): Seq[Byte] =
      badMDNoPad(data, hi.h, hi.key)
    def badMD(data: Seq[Byte], init: Seq[Byte], key: String): Seq[Byte] =
      badMDNoPad(AES.padPKCS7(data, init.length), init, key)
    def badMD(data: Seq[Byte], hi: HashInfo): Seq[Byte] =
      badMD(data, hi.h, hi.key)

    def collideSingle(h: Seq[Byte], key: String): Option[(Seq[Byte], Seq[Byte])] = {
      @tailrec
      def loop(cur: Seq[Byte], found: Map[Seq[Byte], Seq[Byte]]): Option[(Seq[Byte], Seq[Byte])] = {
        val h2 = badMDNoPad(cur, h, key)
        found.get(h2) match {
          case Some(c2) => Some(cur, c2)
          case None =>
            incSeq(cur) match {
              case None => None
              case Some(inc) => loop(inc, found + (h2 -> cur))
            }
        }
      }
      loop(Seq.fill[Byte](h.length)(0), Map())
    }

    type CollisionStream = Stream[(Int, Seq[Byte])]
    def genCollisions(hi: HashInfo): CollisionStream = {
      def loop(prefixes: Seq[(Seq[Byte], Seq[Byte])]): CollisionStream = {
        def getPrefix(n: BigInt) = {
          prefixes.zipWithIndex.foldRight(Seq[Byte]()){case ((pair, i), prefix) =>
            (if(n.testBit(i)) pair._1 else pair._2) ++ prefix
          }
        }

        val maxN = BigInt(2).pow(prefixes.length)
        def innerLoop(n: BigInt): CollisionStream = {
          if(n == maxN) {
            collideSingle(badMDNoPad(getPrefix(0), hi), hi.key) match {
              case Some(pair) => loop(prefixes :+ pair)
              case None => Stream.empty
            }
          } else {
            (prefixes.length, getPrefix(n)) #:: innerLoop(n + 1)
          }
        }

        innerLoop(0)
      }

      loop(Seq())
    }

    def doubleCollision: Option[(Seq[Byte], Seq[Byte])] = {
      @tailrec
      def loop(n: Int, s: CollisionStream, found: Map[Seq[Byte], Seq[Byte]]): Option[(Seq[Byte], Seq[Byte])] = {
        s match {
          case Stream.Empty => None
          case (n2, _) #:: _ if n != n2 => loop(n2, s, Map())
          case (_, p) #:: s2 =>
            val hash = badMDNoPad(p, hi2)
            found.get(hash) match {
              case Some(p2) => Some((p, p2))
              case None => loop(n, s2, found + (hash -> p))
            }
        }
      }

      loop(0, genCollisions(hi1), Map())
    }

    def doubleHash(h: Seq[Byte]): Seq[Byte] =
      badMD(h, hi1) ++ badMD(h, hi2)

    def collideDiffInit(h: (Seq[Byte], Seq[Byte]), key: String): Option[(Seq[Byte], Seq[Byte])] = {
      @tailrec
      def loop(cur: Seq[Byte], found: (Map[Seq[Byte], Seq[Byte]], Map[Seq[Byte], Seq[Byte]])): Option[(Seq[Byte], Seq[Byte])] = {
        val next1 = badMDNoPad(cur, h._1, key)
        val next2 = badMDNoPad(cur, h._2, key)
        (found._1.get(next2), found._2.get(next1)) match {
          case (Some(c), _) => Some(c, cur)
          case (_, Some(c)) => Some(cur, c)
          case _ =>
            incSeq(cur) match {
              case None => None
              case Some(inc) => loop(inc, (found._1 + (next1 -> cur), found._2 + (next2 -> cur)))
            }
        }
      }
      loop(Seq.fill[Byte](h._1.length)(0), (Map(), Map()))
    }

    @tailrec
    def genExpandable(k: Int, h: Seq[Byte], key: String, acc: Seq[(Seq[Byte], Seq[Byte])] = Seq()): Option[(Seq[(Seq[Byte], Seq[Byte])], Seq[Byte])] = {
      val prefix = AES.randomBytes(Math.pow(2, k-1).toInt * h.length)
      val prefixH = badMDNoPad(prefix, h, key)

      collideDiffInit((h, prefixH), key) match {
        case Some((a, b)) =>
          val newAcc = (a, prefix ++ b) +: acc
          val h2 = badMDNoPad(a, h, key)
          if(k == 1) Some((newAcc, h2))
          else genExpandable(k-1, h2, key, newAcc)
        case None => None
      }
    }

    def subhashM(M: Seq[Byte], h: Seq[Byte], key: String): Map[Seq[Byte], Int] = {
      @tailrec
      def loop(M: Seq[Byte], h: Seq[Byte], i: Int, map: Map[Seq[Byte], Int] = Map()): Map[Seq[Byte], Int] = {
        M.splitAt(h.length) match {
          case (Seq(), _) => map
          case (head, tail) =>
            val h2 = badMDNoPad(head, h, key)
            // Note: previous state is added to map
            loop(tail, h2, i + h.length, map + (h -> i))
        }
      }

      val split = (log2(M.length) + 1) * h.length
      val (prefix, rest) = M.splitAt(split)
      loop(rest, badMDNoPad(prefix, h, key), split)
    }

    @tailrec
    def log2(i: Int, acc: Int = 0): Int = {
      if(i > 1) log2(i >>> 1, acc + 1)
      else acc
    }

    def expandable(M: Seq[Byte], hi: HashInfo = hi1): Option[Seq[Byte]] = {
      val k = log2(M.length)
      val subhash = subhashM(M, hi.h, hi.key)
      genExpandable(k, hi.h, hi.key) match {
        case None => None
        case Some((exp, hExp)) =>
          @tailrec
          def findBridge(b: Seq[Byte] = Seq.fill[Byte](hi.h.length)(0)): Option[(Seq[Byte], Int)] = {
            val h = badMDNoPad(b, hExp, hi.key)
            subhash.get(h) match {
              case None =>
                incSeq(b) match {
                  case None => None
                  case Some(x) => findBridge(x)
                }
              case Some(i) => Some((b, i))
            }
          }

          findBridge() match {
            case None => None
            case Some((b, i)) =>
              val expExtraLen = i / hi.h.length - k - 1
              val (start, _) = exp.foldLeft((Seq[Byte](), expExtraLen)){case ((acc, len), (short, long)) =>
                ((if(len % 2 == 0) short else long) ++ acc, len >>> 1)
              }
              Some(start ++ b ++ M.drop(i))
          }
      }
    }

    case class PredictNode(blockL: Seq[Byte], blockR: Seq[Byte], h: Seq[Byte])
    case class PredictInfo(predicts: IndexedSeq[PredictNode]) {
      val map = predicts.take((predicts.length+1)/2).zipWithIndex.foldLeft(Map[Seq[Byte], Int]()){case (m, (p, i)) => m + (p.h -> i)}
    }

    val GLUE_LENGTH = 4

    def predictPart1(k: Int, len: Int, hi: HashInfo): Option[(Seq[Byte], Int, PredictInfo)] = {
      val initVals = IndexedSeq.tabulate(Math.pow(2, k).toInt){_ => PredictNode(Seq(), Seq(), AES.randomBytes(hi.blockLen).toIndexedSeq)}

      // TODO: @tailrec
      def loop(vals: IndexedSeq[PredictNode], k: Int): Option[IndexedSeq[PredictNode]] = {
        if(k == -1)
          Some(vals)
        else {
          val offset = vals.length - Math.pow(2, k + 1).toInt
          val next = IndexedSeq.tabulate(Math.pow(2, k).toInt){n =>
            val a = vals(offset + n * 2)
            val b = vals(offset + n * 2 + 1)
            collideDiffInit((a.h, b.h), hi.key) match {
              case None => return None
              case Some((x, y)) =>
                val h = badMDNoPad(x, a.h, hi.key)
                PredictNode(x, y, h)
            }
          }
          loop(vals ++ next, k - 1)
        }
      }

      loop(initVals, k - 1) match {
        case None => None
        case Some(predicts) => Some((badMD(Seq(), predicts.last.h, hi.key), len + (GLUE_LENGTH + k) * hi.blockLen, PredictInfo(predicts)))
      }
    }

    def predictPart2(m: Seq[Byte], info: PredictInfo, hi: HashInfo): Option[Seq[Byte]] = {
      val h = badMDNoPad(m, hi)

      @tailrec
      def getGlue(b: Seq[Byte] = Seq.fill[Byte](GLUE_LENGTH * hi.blockLen)(0)): Option[(Seq[Byte], Int)] = {
        info.map.get(badMDNoPad(b, h, hi.key)) match {
          case None => incSeq(b) match {
            case None => None
            case Some(b2) => getGlue(b2)
          }
          case Some(i) => Some((b, i))
        }
      }

      def getSuffix(i: Int, predicts: IndexedSeq[PredictNode] = info.predicts): Seq[Byte] = {
        @tailrec
        def loop(i: Int, predicts: IndexedSeq[PredictNode] = info.predicts, acc: Seq[Byte] = Seq()): Seq[Byte] = {
          if(predicts.isEmpty)
            acc
          else {
            val p = predicts(i / 2)
            val block = if(i % 2 == 0) p.blockL else p.blockR
            val newPredicts = predicts.drop((predicts.length+1)/2)
            val newI = i / 2
            loop(newI, newPredicts, acc ++ block)
          }
        }
        loop(i, predicts.drop((predicts.length+1)/2))
      }

      getGlue() match {
        case None => None
        case Some((glue, i)) =>
          val suffix = getSuffix(i)
          Some(m ++ glue ++ suffix)
      }
    }
  }
}
