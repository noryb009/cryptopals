object Utils {
  def binaryToString(data: Seq[Int]) =
    data.map(_.asInstanceOf[Char]).mkString

  def stringToBinary(data: String): Seq[Int] =
    data.getBytes().map(_.asInstanceOf[Int])
}
