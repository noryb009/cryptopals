object XOR {
  def xor(a: Seq[Int], b: Seq[Int]): Seq[Int] =
    a.zip(b).map{case (x,y) => x ^ y}
}
