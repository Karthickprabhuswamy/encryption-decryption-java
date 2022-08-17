package com.ty.aes;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MyAes{
	
	private SecretKey key;
	private int KEY_SIZE=128;
	private int T_LEN=128;
    private	Cipher encryptionCipher;
	
	public void init() throws NoSuchAlgorithmException {
		
			KeyGenerator generator=KeyGenerator.getInstance("AES");
			generator.init(KEY_SIZE);
			key = generator.generateKey();
			
	}
	public String encrypt(String message) throws Exception {
		byte[] messageInBytes = message.getBytes();
		 encryptionCipher= Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE,key);
		byte[]encryptedBytes = encryptionCipher.doFinal(messageInBytes);
		 return encode(encryptedBytes);
		
	}
	public String decrypt(String encrptedMessage)throws Exception{
		byte[] messageInBytes = decode(encrptedMessage);
		Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(T_LEN, encryptionCipher.getIV());
		decryptionCipher.init(Cipher.DECRYPT_MODE,key,spec);
		byte[]decryptedBytes = decryptionCipher.doFinal(messageInBytes);
		 return new String(decryptedBytes);
		
	}
	private String encode(byte[] data){return Base64.getEncoder().encodeToString(data);}
	
	private byte[]decode(String data){return Base64.getDecoder().decode(data);}
	
	public static void main(String[] args) {
		
		MyAes aes = new MyAes();
		
		try {
			aes.init();
			String encryptedMessage= aes.encrypt("HEllo");
			String dencryptedMessage=aes.decrypt(encryptedMessage);
			
			System.out.println("Encrypted Messege--:"+encryptedMessage);
			System.out.println("Decrypted Messege--"+dencryptedMessage);
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
	}}