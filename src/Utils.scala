object Utils {
  def binaryToString(data: Seq[Int]) = {
    data.map(_.toChar).mkString
  }

  def stringToBinary(data: String): Seq[Int] = {
    data.getBytes().map(_.toInt)
  }
}
