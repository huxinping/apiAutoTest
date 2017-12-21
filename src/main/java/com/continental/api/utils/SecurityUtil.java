package com.continental.api.utils;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.digest.DigestUtils;

import sun.misc.BASE64Decoder;

/**
 * copy from app-server
 * Created by  on 15/11/25.
 */
public class SecurityUtil {
    public static final String ALGORITHM_MD5 = "MD5";
    public static final String ALGORITHM_3DES = "DESede";
    private static final String ENCODING_UTF8 = "UTF-8";

    public static final String ALGORITHM_SHA512 = "SHA-512";
    private static final String CONTBOX = "continental_tbox";

    /**
     * 对上送到服务端请求报文加密
     * @param key
     * @param content
     * @return
     * @throws Exception
     * @throws UnsupportedEncodingException
     */
    public static String cryption(String key, String content) throws UnsupportedEncodingException, Exception{
        return byteArray2HexString(encryptMode(hexString2ByteArray(Md5(key)), content.getBytes()));
    }
    /**
     * MD5签名算法 返回 Hex string
     * @param plainText
     * @return
     * @throws Exception
     */
    public static String Md5(String plainText) throws Exception {
        MessageDigest md = MessageDigest.getInstance(ALGORITHM_MD5);
        md.update(plainText.getBytes());
        byte b[] = md.digest();
        int i;
        StringBuilder buf = new StringBuilder("");
        for (int offset = 0; offset < b.length; offset++) {
            i = b[offset];
            if (i < 0)
                i += 256;
            if (i < 16)
                buf.append("0");
            buf.append(Integer.toHexString(i));
        }
        return buf.toString().toUpperCase();

    }

    public static String SHA512(String plainText) throws Exception{
        MessageDigest md = MessageDigest.getInstance(ALGORITHM_SHA512);
        byte[] byteArr = md.digest(plainText.getBytes(ENCODING_UTF8));
        return byteArray2HexString(byteArr);
    }

    //---------------------------------------------------------- private methods ------------------------------------------------------------
    private static byte[] encryptMode(byte[] keybyte, byte[] src) {
        try {
            // 生成密钥
            if (keybyte.length < 24) {
                keybyte = SecurityUtil.convertKey(keybyte);
            }
            SecretKey deskey = new SecretKeySpec(keybyte, ALGORITHM_3DES);
            // 加密
            Cipher c1 = Cipher.getInstance(ALGORITHM_3DES);
            c1.init(Cipher.ENCRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (java.lang.Exception e3) {
            e3.printStackTrace();
        }
        return null;
    }

    // keybyte为加密密钥，长度为24字节
    // src为加密后的缓冲区

    private static byte[] decryptMode(byte[] keybyte, byte[] src) {
        try {
            //System.out.println("key length: " + keybyte.length);
            if (keybyte.length < 24) {
                keybyte = SecurityUtil.convertKey(keybyte);
            }
            SecretKey deskey = new SecretKeySpec(keybyte, ALGORITHM_3DES);
            Cipher c1 = Cipher.getInstance("DESede/ECB/NoPadding");
            c1.init(Cipher.DECRYPT_MODE, deskey);
            return c1.doFinal(src);
        } catch (java.security.NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (javax.crypto.NoSuchPaddingException e2) {
            e2.printStackTrace();
        } catch (java.lang.Exception e3) {
            e3.printStackTrace();
        }
        System.out.println("----------xxxxxxxxxxxxxxx--------");
        return null;
    }

    // 将16字节的密钥转换成24字节
    private static byte[] convertKey(byte[] srcKey) {
        byte[] destKey = null;
        byte[] keyFirst = new byte[8];
        ByteBuffer buffer = ByteBuffer.wrap(srcKey);
        buffer.get(keyFirst);
        buffer.clear();
        buffer = ByteBuffer.allocate(24);
        buffer.put(srcKey);
        buffer.put(keyFirst);
        buffer.flip();
        destKey = buffer.array();
        buffer.clear();
        return destKey;
    }

	/*private static String byteArray2HexString(byte[] arr) {
		StringBuilder sbd = new StringBuilder();
		for (byte b : arr) {
			String tmp = Integer.toHexString(0xFF & b);
			if (tmp.length() < 2)
				tmp = "0" + tmp;
			sbd.append(tmp);
		}
		return sbd.toString();
	}*/

    private static String byteArray2HexString(byte[] byteArr) {
        if(byteArr == null || byteArr.length == 0){
            return null;
        }
        StringBuilder sbd = new StringBuilder("");
        for (byte b : byteArr) {
            String tmp = Integer.toHexString(0xFF & b);
            if (tmp.length() < 2){
                sbd.append(0);
            }
            sbd.append(tmp);
        }
        return sbd.toString();
    }

    private static byte[] hexString2ByteArray(String hexStr) {
        if (hexStr == null)
            return null;
        if (hexStr.length() % 2 != 0) {
            return null;
        }
        byte[] data = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            char hc = hexStr.charAt(2 * i);
            char lc = hexStr.charAt(2 * i + 1);
            byte hb = hexChar2Byte(hc);
            byte lb = hexChar2Byte(lc);
            if (hb < 0 || lb < 0) {
                return null;
            }
            int n = hb << 4;
            data[i] = (byte) (n + lb);
        }
        return data;
    }

    private static byte hexChar2Byte(char c) {
        if (c >= '0' && c <= '9')
            return (byte) (c - '0');
        if (c >= 'a' && c <= 'f')
            return (byte) (c - 'a' + 10);
        if (c >= 'A' && c <= 'F')
            return (byte) (c - 'A' + 10);
        return -1;
    }
    
    // 获取签名：sign
    /* 所有的请求，在请求体中包含请求时间和签名验证，具体的签名方式为：
    Base64Encoding(  MD5Hex ( vincode + "1480573358818" + "continental_tbox")  )
   其中，1480573358818表示当前请求时间，vincode表示车辆唯一标识，"continental_tbox"表示请求的客户端标识（固定值） */
    public static String getSign(String vincode ) {
    	long timestamp = System.currentTimeMillis();
    	String sign = vincode+timestamp+CONTBOX;
//    	return (SecurityUtil.getBASE64(DigestUtils.md5Hex("TB3C17M13051000501480573358818continental_tbox")));
    	return (SecurityUtil.getBASE64(DigestUtils.md5Hex(sign)));
    	
    } 
    
    
     // 将 s 进行 BASE64 编码 
    public static String getBASE64(String s) { 
    	if (s == null) return null; 
    	return (new sun.misc.BASE64Encoder()).encode( s.getBytes() ); 
    } 
     
    // 将 BASE64 编码的字符串 s 进行解码 
    public static String getFromBASE64(String s) { 
    	if (s == null) return null; 
    	BASE64Decoder decoder = new BASE64Decoder(); 
    	try { 
    		byte[] b = decoder.decodeBuffer(s); 
    		return new String(b); 
    	} catch (Exception e) { 
    	return null; 
    	} 
    }
    

    
}