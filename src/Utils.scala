object Utils {
  def binaryToString(data: Seq[Int]) = {
    data..map(x => x.toChar).mkString
  }
}
