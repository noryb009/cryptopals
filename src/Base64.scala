object Base64 {
  val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  val equals = '='.toInt
  val antiChars = chars.zipWithIndex.toMap + ('=' -> equals)

  def encode(data: Seq[Byte]): String =
    data
      .sliding(3, 3)
      .map {
        case Seq(a: Byte, b: Byte, c: Byte) => (3, (a << 16) + (b << 8) + c)
        case Seq(a: Byte, b: Byte)          => (2, (a << 16) + (b << 8))
        case Seq(a: Byte)                   => (1, a << 16)
      }
      .map {case (i, n) => (i, Seq(n >> 18, n >> 12, n >> 6, n).map{x => chars(x & 63)})}

      .flatMap {
        case (3, s)               => s
        case (2, Seq(a, b, c, _)) => Seq(a, b, c, '=')
        case (1, Seq(a, b, _, _)) => Seq(a, b, '=', '=')
      }
      .mkString

  def decode(str: String): Seq[Byte] = {
    str
      .sliding(4, 4)
      .map(_.filter(_ != '='))
      .map(_.map(antiChars))
      .map {
        case Seq(a, b, c, d) => (3, (a << 18) + (b << 12) + (c << 6) + d)
        case Seq(a, b, c)    => (2, (a << 18) + (b << 12) + (c << 6))
        case Seq(a, b)       => (1, (a << 18) + (b << 12))
      }
      .flatMap {
        case (3, n) => Seq(n >> 16, n >> 8, n)
        case (2, n) => Seq(n >> 16, n >> 8)
        case (1, n) => Seq(n >> 16)
      }
      .map(a => (a & 255).toByte)
      .toSeq
  }

  def decodeFile(file: String): Seq[Byte] =
    decode(io.Source.fromFile(file).getLines.foldLeft("")(_ + _))
}
