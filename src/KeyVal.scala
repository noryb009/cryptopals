object KeyVal {
  def clean(str: String): String =
    str.replaceAll("=", "").replaceAll("&", "")

  def apply(str: String): Seq[(String, String)] =
    str.split("&").map(_.split("=", 2) match {
      case Array(k)    => (k, "")
      case Array(k, v) => (k, v)
    })

  def apply(data: Seq[(String, String)]): String =
    data.map{case (a, b) => clean(a) + "=" + clean(b)}.mkString("&")

  def profileFor(email: String): String = {
    KeyVal(Seq(("email", email), ("uid", "10"), ("role", "user")))
  }

  def encryptProfileGen(email: String, key: String): Seq[Byte] =
    AES.encrypt(AES.padPKCS7(Utils.stringToBinary(profileFor(email))), key)

  def isAdmin(data: Seq[Byte], key: String): Boolean =
    AES.unpadPKCS7(AES.decrypt(data, key)) match {
      case Some(x) =>
        KeyVal(Utils.binaryToString(x)).exists{case (k, v) => k == "role" && v == "admin"}
      case None => false
    }

  def makeAdmin(encryptor: (String => Seq[Byte])): Seq[Byte] = {
    // Get parts:
    // - email=a@aaaaaaaa admin\x0B (11 times)
    val email1 = /* "email=" + */ "a@aaaaaaa." + AES.padPKCS7("admin", 16) // + ...
    val enc1 = encryptor(email1)
    // - email=a@aaaaaaaa aaa&uid=10&role=
    val email2 = /* "email=" + */ ".........." + "com" // + "&uid=10&role="
    val enc2 = encryptor(email2)

    // Then stitch together: email1(0) + email2(1) + email1(1)
    enc1.slice(0, 16) ++ enc2.slice(16, 32) ++ enc1.slice(16, 32)
  }

  def checkMakeAdmin: Boolean = {
    val key = AES.randomString(16)
    val encryptor = (email: String) => encryptProfileGen(email, key)
    val enc = makeAdmin(encryptor)
    isAdmin(enc, key)
  }
}
