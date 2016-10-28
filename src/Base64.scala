object Base64 {
  val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

  def encode(data: Seq[Int]): String =
    data
      .padTo(data.length + ((3 - (data.length % 3)) % 3), '=')
      .sliding(3, 3)
      .map {case Seq(a: Int, b: Int, c: Int) => (a << 16) + (b << 8) + c}
      .flatMap(n => Seq(n >> 18, n >> 12, n >> 6, n))
      .map(a => chars(a & 63))
      .mkString
}
