# GMSSL
GMSSL国密sm2加解密
#使用方法
*支持真机，模拟器*
//这里需要用到公钥和私钥

// 加密 用公钥\
`[GMSm2Utils encryptText:@"aaaaa" publicKey:self.publicKey];`


// 解密 用私钥\
`[GMSm2Utils decryptToText:self.encryptHexLabel.text privateKey:self.privateKey];`
