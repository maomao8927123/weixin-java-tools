package cn.binarywang.wx.miniapp.util.crypt;

import cn.binarywang.wx.miniapp.config.WxMaConfig;
import me.chanjar.weixin.common.util.crypto.PKCS7Encoder;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;

/**
 * @author <a href="https://github.com/binarywang">Binary Wang</a>
 */
public class WxMaCryptUtils extends me.chanjar.weixin.common.util.crypto.WxCryptUtil {
  public WxMaCryptUtils(WxMaConfig config) {
    this.appidOrCorpid = config.getAppid();
    this.token = config.getToken();
    this.aesKey = Base64.decodeBase64(config.getAesKey() + "=");
  }

  /**
   * AES解密
   *
   * @param encryptedData 消息密文
   * @param ivStr         iv字符串
   */
  public static String decrypt(String sessionKey, String encryptedData, String ivStr) {
    try {
      AlgorithmParameters params = AlgorithmParameters.getInstance("AES");
      params.init(new IvParameterSpec(Base64.decodeBase64(ivStr)));
      int base = 16;
      byte[] keyByte = Base64.decodeBase64(sessionKey);
      if (keyByte.length % base != 0) {
            int groups = keyByte.length / base + (keyByte.length % base != 0 ? 1 : 0);
            byte[] temp = new byte[groups * base];
            Arrays.fill(temp, (byte) 0);
            System.arraycopy(keyByte, 0, temp, 0, keyByte.length);
            keyByte = temp;
      }
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyByte, "AES"), params);

      return new String(PKCS7Encoder.decode(cipher.doFinal(Base64.decodeBase64(encryptedData))), StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new RuntimeException("AES解密失败", e);
    }
  }

}
