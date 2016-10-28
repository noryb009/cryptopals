object Hex {
  def decode(str: String): Seq[Int] =
    str.sliding(2, 2).map(Integer.valueOf(_, 16).toInt).toList // toSeq is a stream
}
