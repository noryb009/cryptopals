object XOR {
  def xor(a: Seq[Int], b: Seq[Int]): Seq[Int] =
    a.zip(b).map{case (x,y) => x ^ y}

  def xor(a: Seq[Int], b: Int): Seq[Int] =
    a.map{_ ^ b}

  def singleByte(data: Seq[Int]): Seq[Int] = {
    def scoreSingle(n: Int): Option[Int] = {
      val xored = xor(data, n)
      if(xored.intersect((0 to 8) ++ (14 to 21) ++ Seq(11, 12, 127)).nonEmpty)
        None
      else
        Some(xored.count{
          case ' ' | 'e' => true
          case _ => false
        })
    }

    val maxN = (0 to 255)
      .map(scoreSingle)
      .zipWithIndex
      .flatMap{
        case (Some(x), i) => Some(x, i)
        case _ => None
      }.max._2
    xor(data, maxN)
  }
}
