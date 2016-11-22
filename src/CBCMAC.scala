object CBCMAC {
  def apply(data: Seq[Byte], key: String, iv: Option[Seq[Byte]] = None): Seq[Byte] =
    AES.encryptCBC(AES.padPKCS7(data), key, iv).takeRight(16)

  object Forge {
    def splitParts(m: Seq[Byte]): (Seq[Byte], Seq[Byte], Seq[Byte]) = {
      val (m2, mac) = m.splitAt(m.length - 16)
      val (data, iv) = m2.splitAt(m2.length - 16)
      (data, iv, mac)
    }

    def splitPartsFixedIV(m: Seq[Byte]): (Seq[Byte], Seq[Byte]) =
      m.splitAt(m.length - 16)

    def serverInner(message: Seq[Byte], key: String, mac: Seq[Byte], iv: Option[Seq[Byte]]): Option[KeyVal.Pairs] = {
      val exp = CBCMAC(message, key, iv)
      if(exp != mac)
        None
      else
        Some(KeyVal(Utils.binaryToString(message)))
    }

    def server(key: String, req: Seq[Byte]): Option[KeyVal.Pairs] = {
      val (message, iv, mac) = splitParts(req)
      serverInner(message, key, mac, Some(iv))
    }

    def serverFixedIV(key: String, req: Seq[Byte]): Option[KeyVal.Pairs] = {
      val (message, mac) = splitPartsFixedIV(req)
      serverInner(message, key, mac, None)
    }

    def clientReq(key: String, from: Int)(to: Int, amount: BigInt): Seq[Byte] = {
      val iv = AES.randomBytes(16)
      val text = s"from=$from&to=$to&amount=$amount"
      val message = Utils.stringToBinary(text)
      val mac = CBCMAC(message, key, Some(iv))
      message ++ iv ++ mac
    }

    def clientReqFixedIV(key: String, from: Int)(tx: Seq[(Int, BigInt)]): Seq[Byte] = {
      val txstr = tx.map{case (to, amount) => s"$to:$amount"}.mkString(";")
      val text = s"from=$from&tx_list=$txstr"
      val message = Utils.stringToBinary(text)
      val mac = CBCMAC(message, key)
      message ++ mac
    }

    /* The attacker owns both acc1 and acc2,
     * and victim's ID has at most the same number of digits in acc1.
     */
    def forge(client: (Int, BigInt) => Seq[Byte], victim: Int, acc1: Int, acc2: Int): Seq[Byte] = {
      val (data, iv, mac) = splitParts(client(acc2, 1000000))
      val text = Utils.binaryToString(data)
      val fromStr = Utils.stringToBinary(acc1.toString)
      val victimStrPrime = Utils.stringToBinary(victim.toString)
      val victimStr = Seq.fill[Byte](fromStr.length - victimStrPrime.length)('0') ++ victimStrPrime

      val acc1Start = text.indexOf("from=") + 5
      val xor = Seq.fill[Byte](acc1Start)(0) ++ XOR.xor(victimStr, fromStr.toIndexedSeq) ++ Seq.fill[Byte](16 - acc1Start - victimStr.length)(0)
      val newIV = XOR.xor(iv, xor.toIndexedSeq)

      val newText = text.replace(acc1.toString, ("0" * (fromStr.length - victimStrPrime.length)) ++ victim.toString)
      val newData = Utils.stringToBinary(newText)

      newData ++ newIV ++ mac
    }

    /* This assumes that each transaction fails independently.
     *
     * This also assumes the client can generate a request to transfer more
     * than the amount in the account.
     */
    def forgeFixedIV(client: Seq[(Int, BigInt)] => Seq[Byte], captured: Seq[Byte], to: Int): Seq[Byte] = {
      /* We have C|C|C, and mac = M
       * and G|G|G, and mac = N
       * We want C|C|C|G|G|G, mac = O
       * We know N != O != M, but
       * C|C|C|(G^M)|G|G, mac = T = N
       *
       * We can have G = "from=...&..." + "[tx_list=]##:to=amount"
       * then we can convert G to garbage.
       */
      val (capMsg, capMac) = splitPartsFixedIV(captured)
      val c = AES.padPKCS7(capMsg)

      val gRes = client(Seq((1, BigInt(0)), (to, BigInt(1000000))))
      val (g, gMac) = splitPartsFixedIV(gRes)
      val (gStart, gEnd) = g.splitAt(16)
      val gMod = XOR.xor(gStart, capMac.toIndexedSeq) ++ gEnd
      c ++ gMod ++ gMac
    }
  }
}
