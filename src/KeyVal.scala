import scala.annotation.tailrec

object KeyVal {
  case class Pair(k: String, v: String)

  case class Pairs(pairs: Seq[Pair]) {
    def apply(key: String): Option[String] =
      pairs.collectFirst{case Pair(k, v) if k == key => v}

    def mkString(splitter: String = "&"): String =
      pairs.map{case Pair(a, b) => clean(a) + "=" + clean(b)}.mkString(splitter)
  }

  def clean(str: String, toClean: Seq[String] = Seq("=", "&")): String =
    toClean.foldLeft(str)(_.replaceAll(_, ""))

  def apply(str: String, splitter: String = "&"): Pairs =
    Pairs(str.split(splitter).map(_.split("=", 2) match {
      case Array(k)    => Pair(k, "")
      case Array(k, v) => Pair(k, v)
    }))

  def profileFor(email: String): String =
    Pairs(Seq(Pair("email", email), Pair("uid", "10"), Pair("role", "user"))).mkString()

  def encryptProfileGen(email: String, key: String): Seq[Byte] =
    AES.encrypt(AES.padPKCS7(Utils.stringToBinary(profileFor(email))), key)

  def isAdmin(data: Seq[Byte], key: String, value: String, splitter: String = "&"): Boolean =
    KeyVal(Utils.binaryToString(data), splitter)(key).contains(value)

  def isAdminAnd(data: Seq[Byte], key: String): Boolean =
    AES.unpadPKCS7(AES.decrypt(data, key)) match {
      case Some(x) => isAdmin(x, "role", "admin")
      case None => false
    }

  type Encryptor = String => Seq[Byte]

  def makeAdmin(encryptor: Encryptor): Seq[Byte] = {
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
    isAdminAnd(enc, key)
  }

  val c1: String = "comment1=cooking" + "%20MCs;userdata="
  val c2: String = ";comment2=%20lik" + "e%20a%20pound%20" + "of%20bacon"

  def encryptComments(userdata: String, key: String): Seq[Byte] =
    AES.encryptCBC(AES.padPKCS7(Utils.stringToBinary(c1 ++ userdata ++ c2)), key)

  def encryptCommentsCTR(userdata: String, key: AES.KeyStream): Seq[Byte] =
    AES.encryptCTR(Utils.stringToBinary(c1 ++ userdata ++ c2), key)

  def invStr(s: String): String =
    Utils.binaryToString(XOR.xor(Utils.stringToBinary(s), 1.toByte))

  def makeAdminSemi(encryptor: Encryptor) = {
    val data1 = "a" * 16
    val data2 = invStr("aaaaa;admin=true")
    val enc = encryptor(data1 ++ data2)

    val a = enc.slice(0, 16*2)
    val b = XOR.xor(enc.slice(16*2, 16*3), 1.toByte)
    val c = enc.splitAt(16*3)._2
    val d = a ++ b ++ c
    d
  }

  def makeAdminSemiCTR(encryptor: Encryptor): Seq[Byte] = {
    val data = ";admin=true"
    val inv = invStr(data)
    val enc = encryptor(inv)

    val a = Seq.fill[Byte](c1.length)(0) ++ Seq.fill[Byte](inv.length)(1) ++ Seq.fill[Byte](c2.length)(0)
    XOR.xor(enc, a.toIndexedSeq)
  }
  def isAdminSemi(data: Seq[Byte], key: String): Boolean = {
    AES.unpadPKCS7(AES.decryptCBC(data, key)) match {
      case Some(x) => isAdmin(x, "admin", "true", ";")
      case None => false
    }
  }

  def isAdminSemiCTR(data: Seq[Byte], key: AES.KeyStream): Boolean =
    isAdmin(AES.decryptCTR(data, key), "admin", "true", ";")

  def checkMakeAdminSemi: Boolean = {
    val key = AES.randomString(16)
    val encryptor = (userdata: String) => encryptComments(clean(userdata, Seq(";", "=")), key)
    val enc = makeAdminSemi(encryptor)
    isAdminSemi(enc, key)
  }

  def checkMakeAdminSemiCTR: Boolean = {
    val key = AES.genKeyStream(AES.randomString(16))
    val encryptor = (userdata: String) => encryptCommentsCTR(clean(userdata, Seq(";", "=")), key)
    val enc = makeAdminSemiCTR(encryptor)
    isAdminSemiCTR(enc, key)
  }

  type CheckHMAC = (Seq[Byte], Seq[Byte]) => Boolean

  type AppendHMAC = (Seq[Byte], Seq[Byte], Int) => Seq[Byte]
  type GenPadding = (Int) => Seq[Byte]
  def appendHMAC(data: Seq[Byte], suffix: Seq[Byte], hmac: Seq[Byte], checkHMAC: CheckHMAC, append: AppendHMAC, genPadding: GenPadding) = {
    @tailrec
    def inner(keyLen: Int): (Seq[Byte], Seq[Byte]) = {
      val origLen = data.length + keyLen
      val newHMAC = append(hmac, suffix, origLen)
      val paddedData = data ++ genPadding(origLen) ++ suffix
      if(checkHMAC(paddedData, newHMAC))
        (paddedData, newHMAC)
      else
        inner(keyLen + 1)
    }

    inner(0)
  }

  def appendSha1HMAC(data: Seq[Byte], suffix: Seq[Byte], hmac: Seq[Byte], checkHMAC: CheckHMAC): (Seq[Byte], Seq[Byte]) =
    appendHMAC(data, suffix, hmac, checkHMAC, Hash.appendSha1, Hash.sha1Padding)

  def appendMD4HMAC(data: Seq[Byte], suffix: Seq[Byte], hmac: Seq[Byte], checkHMAC: CheckHMAC): (Seq[Byte], Seq[Byte]) =
    appendHMAC(data, suffix, hmac, checkHMAC, Hash.appendMD4, Hash.md4Padding)
}
