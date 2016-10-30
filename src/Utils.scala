object Utils {
  def binaryToString(data: Seq[Byte]) =
    data.map(_.asInstanceOf[Char]).mkString

  def stringToBinary(data: String): Seq[Byte] =
    data.getBytes
}
