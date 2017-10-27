/**
 * @author YASIN
 * @version [PABank V01,17/5/9]
 * @date 17/5/9
 * @description
 *
 * 第一步: 引入js库
 * <script type="text/javascript" src="../../../static/libs/crypto/tripledes.js" ></script>
 * <script type="text/javascript" src="../../../static/libs/crypto/mode-ecb.js" ></script>
 * 第二步:引入CryptoUtils.js
 * import {encryptByDES,decryptByDESModeEBC} as CryptoUtils from '../util/CryptoUtils'
 * 第三步:调起加密解密
 *
 */

/**
 *
 * @param message 需要加密的内容(utf-8)
 * @param key 加密的密钥
 * @returns {*} 加密过后的内容(base64加密)
 */
export function encryptByDES (message, key) {
  let encrypt = window.CryptoJS
  if (!encrypt) {
    return message
  }
  let keyHex = encrypt.enc.Utf8.parse(key)
  let encrypted = encrypt.DES.encrypt(message, keyHex, {
    mode: encrypt.mode.ECB,
    padding: encrypt.pad.Pkcs7
  })
  console.log('a+++++=' + encrypted.ciphertext.toString())
  console.log('abbb+++++=' + encrypted.toString())
  return encrypted.toString()
}
/**
 * @param ciphertext 需要解密的内容(base64)
 * @param key 加密的密钥
 * @returns {*} 解密过后的内容(utf8)
 */
export function decryptByDESModeEBC (message, key) {
  let encrypt = window.CryptoJS
  if (!encrypt) {
    return message
  }
  let keyHex = encrypt.enc.Utf8.parse(key)
  let strBase64 = encrypt.enc.Base64.parse(message)
  let decrypted = encrypt.DES.decrypt({
    ciphertext: strBase64
  }, keyHex, {
    mode: encrypt.mode.ECB,
    padding: encrypt.pad.Pkcs7
  })
  let resultValue = decrypted.toString(encrypt.enc.Utf8)
  return resultValue
}
export function decryptByDESModeEBCHex (message, key) {
  let encrypt = window.CryptoJS
  if (!encrypt) {
    return message
  }
  let keyHex = encrypt.enc.Utf8.parse(key)
  // let strBase64 = encrypt.enc.Base64.parse(message)
  let strHex = encrypt.enc.Hex.parse(message)
  let decrypted = encrypt.DES.decrypt({
    ciphertext: strHex
  }, keyHex, {
    mode: encrypt.mode.ECB,
    padding: encrypt.pad.Pkcs7
  })
  let resultValue = decrypted.toString(encrypt.enc.Utf8)
  return resultValue
}

export function ald () {
  let bow = window.aladdin
  console.log(bow)
}
