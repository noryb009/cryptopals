import scala.annotation.tailrec

object XOR {
  def xor(a: Seq[Int], key: IndexedSeq[Int]): Seq[Int] =
    a.zipWithIndex.map{case (v, i) => v ^ key(i % key.size)}

  def xor(a: Seq[Int], k: Int): Seq[Int] =
    a.map{_ ^ k}

  def singleScore(data: Seq[Int]): Option[(Int, Int)] = {
    def scoreSingle(k: Int): Option[Int] = {
      val xored = xor(data, k)
      xored.intersect((0 to 8) ++ (14 to 21) ++ (127 to 255) ++ Seq(11, 12)) match {
        case Seq() => Some(xored.count {
          case ' ' | 'a' | 'e' | 'i' | 'o' | 'u' => true
          case _ => false
        })
        case _ => None
      }
    }

    (0 to 255)
      .map(scoreSingle)
      .zipWithIndex
      .flatMap{
        case (Some(s), k) => Some(s, k)
        case _ => None
      } match {
      case Seq() => None
      case all => Some(all.maxBy(_._1))
    }
  }

  def singleByte(data: Seq[Int]): Option[Seq[Int]] =
    singleScore(data).map{case (_, k) => xor(data, k)}

  def decryptOneOf(data: Seq[Seq[Int]]): Seq[Int] =
    data.map(singleScore).zipWithIndex.collect{case (Some((s, k)), i) => (s, k, i)} match {
      case Seq() => Seq()
      case all => all.max match {
        case (_, k, i) => xor(data(i), k)
      }
    }


  def hammingDistance(a: Int, b: Int): Int = {
    @tailrec
    def numberOfBits(a: Int, acc: Int = 0): Int = a match {
      case 0 => acc
      case _ => numberOfBits(a >> 1, acc + a & 1)
    }

    numberOfBits(a ^ b)
  }

  def hammingDistance(a: Seq[Int], b: Seq[Int]): Int =
    a.zip(b).map{case (x, y) => hammingDistance(x, y)}.sum

  def hammingDistance(d: (Seq[Int], Seq[Int])): Int = hammingDistance(d._1, d._2)

  def findKeySize(data: Seq[Int], blocks: Int = 4, min: Int = 2, max: Int = 40): Seq[Int] = {
    def findScore(size: Int): Double =
      data
        .sliding(size*2, size)
        .take(blocks)
        .map{block => hammingDistance(block.splitAt(size))}
        .sum
        .toDouble / size

    (min to max).map{size => (findScore(size), size)}.sortBy(- _._1).map(_._2)
  }

  def transpose(data: Seq[Int], size: Int): Seq[Seq[Int]] =
    data
      .sliding(size, size)
      .map(_.padTo(size, 0))
      .toSeq
      .transpose

  def untranspose(data: Seq[Seq[Int]]): Seq[Int] =
    data
      .transpose
      .flatten


  def decryptKnownKeySize(data: Seq[Int], size: Int): Option[Seq[Int]] = {
    val decrypted = transpose(data, size).map {blk => singleByte(blk)}

    decrypted
      .foldLeft[Option[Seq[Seq[Int]]]](Some(Seq())){
        (c, r) => c.flatMap{acc => r.map{item => acc :+ item}}
      }
      .map(untranspose)
      .map(_.take(data.length))
  }

  def decryptUnknownKeySize(data: Seq[Int]): Option[Seq[Int]] =
    findKeySize(data).view.map{decryptKnownKeySize(data, _)}.collectFirst{case Some(x) => x}
}
