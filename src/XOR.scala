object XOR {
  def xor(a: Seq[Int], key: IndexedSeq[Int]): Seq[Int] =
    a.zipWithIndex.map{case (v, i) => v ^ key(i % key.size)}

  def xor(a: Seq[Int], k: Int): Seq[Int] =
    a.map{_ ^ k}

  def singleScore(data: Seq[Int]): Option[(Int, Int)] = {
    def scoreSingle(k: Int): Option[Int] = {
      val xored = xor(data, k)
      xored.intersect((0 to 8) ++ (14 to 21) ++ Seq(11, 12, 127)) match {
        case Seq() => Some(xored.count {
          case ' ' | 'e' => true
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

  def singleByte(data: Seq[Int]): Seq[Int] = {
    singleScore(data) match {
      case Some((_, k)) => xor(data, k)
      case None => Seq()
    }
  }

  def decryptOneOf(data: Seq[Seq[Int]]): Seq[Int] = {
    data.flatMap(singleScore) match {
      case Seq() => Seq()
      case all => all.zipWithIndex.max match {
        case ((_, k), i) => xor(data(i), k)
      }
    }
  }
}
