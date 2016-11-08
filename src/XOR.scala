import scala.annotation.tailrec

object XOR {
  def xor(a: Seq[Byte], key: IndexedSeq[Byte]): Seq[Byte] =
    a.zipWithIndex.map{case (v, i) => (v ^ key(i % key.size)).toByte}

  def xor(a: Seq[Byte], k: Byte): Seq[Byte] =
    a.map{x => (x ^ k).toByte}

  def xorStream(a: Seq[Byte], k: Stream[Byte]): Seq[Byte] =
    xor(a, k.take(a.length).toIndexedSeq)

  def xorEnd(a: Seq[Byte], b: Seq[Byte]) =
    xor(a, IndexedSeq.fill[Byte](a.length - b.length)(0) ++ b)

  def singleScore(data: Seq[Byte]): Option[(Int, Byte)] = {
    def scoreSingle(k: Byte): Option[Int] = {
      val xored = xor(data, k)
      xored.intersect((-128 to 8) ++ (14 to 21) ++ Seq(11, 12, 127)) match {
        case Seq() => Some(xored.map{
          case ' ' | 'a' | 'e' | 'i' | 'o' | 'u' => 3
          case x if x >= 'a' && x <= 'z' => 2
          case x if x >= 'A' && x <= 'Z' => 2
          case ',' | '/' => 1
          case _ => 0
        }.sum)
        case _ => None
      }
    }

    (0 to 255)
      .map{x => scoreSingle(x.toByte)}
      .zipWithIndex
      .flatMap{
        case (Some(s), k) => Some(s, k.toByte)
        case _ => None
      } match {
      case Seq() => None
      case all => Some(all.maxBy(_._1))
    }
  }

  def singleByte(data: Seq[Byte]): Option[Seq[Byte]] =
    singleScore(data).map{case (_, k) => xor(data, k)}

  def decryptOneOf(data: Seq[Seq[Byte]]): Seq[Byte] =
    data.map(singleScore).zipWithIndex.collect{case (Some((s, k)), i) => (s, k, i)} match {
      case Seq() => Seq()
      case all => all.max match {
        case (_, k, i) => xor(data(i), k)
      }
    }


  def hammingDistance(a: Byte, b: Byte): Int = {
    @tailrec
    def numberOfBits(a: Int, acc: Int = 0): Int = a match {
      case 0 => acc
      case _ => numberOfBits(a >> 1, acc + a & 1)
    }

    numberOfBits(a ^ b)
  }

  def hammingDistance(a: Seq[Byte], b: Seq[Byte]): Int =
    a.zip(b).map{case (x, y) => hammingDistance(x, y)}.sum

  def hammingDistance(d: (Seq[Byte], Seq[Byte])): Int = hammingDistance(d._1, d._2)

  def findKeySize(data: Seq[Byte], blocks: Int = 4, min: Int = 2, max: Int = 40): Seq[Int] = {
    def findScore(size: Int): Double =
      data
        .sliding(size*2, size)
        .take(blocks)
        .map{block => hammingDistance(block.splitAt(size))}
        .sum
        .toDouble / size

    (min to max).map{size => (findScore(size), size)}.sortBy(- _._1).map(_._2)
  }

  def transpose(data: Seq[Byte], size: Int): Seq[Seq[Byte]] =
    data
      .grouped(size)
      .map(_.padTo(size, 0.asInstanceOf[Byte]))
      .toSeq
      .transpose

  def untranspose(data: Seq[Seq[Byte]]): Seq[Byte] =
    data
      .transpose
      .flatten


  def decryptKnownKeySize(data: Seq[Byte], size: Int): Option[Seq[Byte]] = {
    val decrypted = transpose(data, size).map {blk => singleByte(blk)}

    decrypted
      .foldLeft[Option[Seq[Seq[Byte]]]](Some(Seq())){
        (c, r) => c.flatMap{acc => r.map{item => acc :+ item}}
      }
      .map(untranspose)
      .map(_.take(data.length))
  }

  def decryptUnknownKeySize(data: Seq[Byte]): Option[Seq[Byte]] =
    findKeySize(data).view.map{decryptKnownKeySize(data, _)}.collectFirst{case Some(x) => x}
}
