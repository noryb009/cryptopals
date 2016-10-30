object Hex {
  def decode(str: String): Seq[Byte] =
    str.sliding(2, 2).map(Integer.valueOf(_, 16).toByte).toSeq

  def encode(data: Seq[Byte]): String =
    data.foldLeft("")(_ + "%02x".format(_))

  def decodeLines(file: String): Seq[Seq[Byte]] =
    io.Source.fromFile(file).getLines.toSeq.map(decode)
}
