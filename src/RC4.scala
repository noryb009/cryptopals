import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

import scala.annotation.tailrec
import scala.collection.mutable

object RC4 {
  case class RC4Env(key: IndexedSeq[Byte]) {
    val maxByte = 256
    def pos(b: Byte): Int = if(b < 0) b + maxByte else b
    def swapK(k: IndexedSeq[Int], i: Int, j: Int): IndexedSeq[Int] = {
      val tmp = k(i)
      k.patch(i, Seq(k(j)), 1).patch(j, Seq(tmp), 1)
    }
    @tailrec
    final def genKey(i: Int = 0, jOld: Int = 0, kOld: IndexedSeq[Int] = 0 until maxByte): IndexedSeq[Int] = {
      if(i >= maxByte)
        kOld
      else {
        val j = (jOld + kOld(i) + pos(key(i % key.length))) % maxByte
        val k = swapK(kOld, i, j)
        genKey(i + 1, j, k)
      }
    }

    val k = genKey()

    def rc4Stream: Stream[Byte] = {
      def loop(iOld: Int = 0, jOld: Int = 0, kOld: IndexedSeq[Int] = k): Stream[Byte] = {
        val i = (iOld + 1) % maxByte
        val j = (jOld + kOld(i)) % maxByte
        val k = swapK(kOld, i, j)
        k((k(i) + k(j)) % maxByte).toByte #:: loop(i, j, k)
      }

      loop(0, 0, k)
    }

    def encrypt(text: Seq[Byte]): Seq[Byte] =
      XOR.xorStream(text, rc4Stream)
  }

  val pure = false
  def encrypt(data: Seq[Byte], key: Seq[Byte] = AES.randomBytes(16)): Seq[Byte] = {
    if(pure)
      RC4Env(key.toIndexedSeq).encrypt(data)
    else {
      def getRC4Cipher(key: Seq[Byte]): Cipher = {
        val c = Cipher.getInstance("RC4")
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.toArray, "RC4"))
        c
      }
      val s = Hex.encode(key)
      getRC4Cipher(key).doFinal(data.toArray)
    }
  }
  val decrypt = encrypt _

  def encryptOracle(text: Seq[Byte])(prefix: Seq[Byte]): Seq[Byte] =
    encrypt(prefix ++ text)

  def byteBias(oracle: (Seq[Byte]) => Seq[Byte]): Seq[Byte] = {
    val len = oracle(Seq()).length

    def index16Stream(offset: Int): () => Seq[Byte] = {
      val padding = Seq.fill(15 - offset)(0.toByte)

      def inner: Seq[Byte] = {
        val t = oracle(padding).zipWithIndex
        t.filter {case(_, i) => i % 16 == 15}.map(_._1)
      }

      inner _
    }

    val valuesInByte = 256
    val byteMask = valuesInByte - 1
    val iterations = Math.pow(2, 21).toInt

    def genDigitColumns() = (0 until Math.min(16, len)).par.map{n =>
      val s = index16Stream(n)
      val numCounts = s().length
      val initialCounts = Seq.tabulate(numCounts)(_ => mutable.ArraySeq.fill[Long](valuesInByte)(0))

      val byteCounts: Seq[Seq[Long]] =
        if(pure) {
          (0 until iterations).foldLeft(initialCounts){(counts, _) =>
            val ss = s()
            ss.zip(counts).map{case (b, c) =>
              val byteAbs = (b + valuesInByte) & byteMask
              c.updated(byteAbs, c(byteAbs) + 1)
            }
          }
        } else {
          (0 until iterations).foreach{_ =>
            val ss = s()
            ss.zipWithIndex.foreach{case (b, ind) =>
              val byteAbs = (b + valuesInByte) & byteMask
              initialCounts(ind)(byteAbs) += 1
            }
          }
          initialCounts
        }

      def byteValue(seq: Seq[Long], index: Int, offset: Int): Long = {
        // Limit the search space. This could be removed, but the number of iterations would then need to be increased.
        if (index != ' ' && (index < 'A' || index > 'Z'))
          0
        else {
          // Offset is the group of 16 the item is in. For the nth item with n % 16 = 0, there are peaks at 0, n,
          // and 256-n. Since the biggest peak is at the third position, multiply its value by 2 to amplify the peak.
          val a = index ^ 0
          val b = index ^ (16 * (offset + 1))
          val c = index ^ (256 - (16 * (offset + 1)))
          seq(a) + seq(b) + seq(c) * 2
        }
      }

      val byteVals = byteCounts.zipWithIndex.map{case(seq, offset) => (0 until valuesInByte).map{index =>
        byteValue(seq, index, offset)
      }}
      val maxVal = byteVals.map(_.zipWithIndex.maxBy{case(byteVal, _) => byteVal}._2.toByte)

      maxVal
    }.toList

    // digitColumns is an array of arrays of bytes. digitColumns(0) holds the 1st, 16th, etc. item in the output. We must transpose this.
    // Transpose into one seq.
    @tailrec
    def transpose(l: Seq[Seq[Byte]], acc: Seq[Byte] = Seq()): Seq[Byte] = {
      if(l.isEmpty)
        acc
      else {
        val nonEmpty = l.filter(_.nonEmpty)
        val acc2 = acc ++ nonEmpty.map(_.head)
        transpose(nonEmpty.map(_.tail), acc2)
      }
    }

    transpose(genDigitColumns())
  }
}
