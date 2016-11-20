object CBCMAC {
  def apply(data: Seq[Byte], key: String, iv: Option[Seq[Byte]] = None): Seq[Byte] =
    AES.encryptCBC(AES.padPKCS7(data), key, iv).takeRight(16)

  object Forge {
    def splitParts(m: Seq[Byte]): (Seq[Byte], Seq[Byte], Seq[Byte]) = {
      val (m2, mac) = m.splitAt(m.length - 16)
      val (data, iv) = m2.splitAt(m2.length - 16)
      (data, iv, mac)
    }

    def server(key: String, req: Seq[Byte]): Option[KeyVal.Pairs] = {
      val (message, iv, mac) = splitParts(req)
      val exp = CBCMAC(message, key, Some(iv))
      if(exp != mac)
        None
      else
        Some(KeyVal(Utils.binaryToString(message)))
    }

    def clientReq(key: String, from: Int)(to: Int, amount: Int): Seq[Byte] = {
      val iv = AES.randomBytes(16)
      val text = s"from=$from&to=$to&amount=$amount"
      val message = Utils.stringToBinary(text)
      val mac = CBCMAC(message, key, Some(iv))
      message ++ iv ++ mac
    }

    /* The attacker owns both acc1 and acc2,
     * and victim's ID has at most the same number of digits in acc1.
     */
    def forge(client: (Int, Int) => Seq[Byte], victim: Int, acc1: Int, acc2: Int): Seq[Byte] = {
      val (data, iv, mac) = splitParts(client(acc2, 1000000))
      val text = Utils.binaryToString(data)
      val fromStr = Utils.stringToBinary(acc1.toString)
      val victimStrPrime = Utils.stringToBinary(victim.toString)
      val victimStr = Seq.fill[Byte](fromStr.length - victimStrPrime.length)(0) ++ victimStrPrime

      val acc1Start = text.indexOf("from=") + 5
      val xor = Seq.fill[Byte](acc1Start)(0) ++ XOR.xor(victimStr, fromStr.toIndexedSeq) ++ Seq.fill[Byte](16 - acc1Start - victimStr.length)(0)
      val newIV = XOR.xor(iv, xor.toIndexedSeq)

      val newText = text.replace(acc1.toString, ("0" * (fromStr.length - victimStrPrime.length)) ++ victim.toString)
      val newData = Utils.stringToBinary(newText)

      newData ++ newIV ++ mac
    }
  }
}
