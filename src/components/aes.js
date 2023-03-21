let CryptoJS = require("crypto-js");
export class AESUtil {
  generateKey(salt, phrase) {
    return CryptoJS.PBKDF2(phrase, CryptoJS.enc.Utf8.parse(salt), {
      keySize: 128,
      iterations: 1000,
    });
  }

  encrypt(iv, phrase, plainText) {
    let salt = CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex);
    let key = this.generateKey(salt, phrase);
    let encrypted = CryptoJS.AES.encrypt(plainText, key, {
      iv: CryptoJS.enc.Hex.parse(iv),
    });
    let payload = encrypted.ciphertext.toString(CryptoJS.enc.Base64);
    return {
      salt,
      payload,
    };
  }

  decrypt(iv, phrase, salt, cipherText) {
    let key = this.generateKey(salt, phrase);
    let cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: CryptoJS.enc.Base64.parse(cipherText),
    });
    let decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
      iv: CryptoJS.enc.Hex.parse(iv),
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
  }
}

export const aesUtil = new AESUtil();
