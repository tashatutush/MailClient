package app;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import org.apache.xml.security.utils.JavaUtils;

import com.google.api.services.gmail.Gmail;

import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {

	private static final String KEY_FILE = "./data/session.key";
	private static final String IV1_FILE = "./data/iv1.bin";
	private static final String IV2_FILE = "./data/iv2.bin";
	
	public static void main(String[] args) {
		
        try {
        	Gmail service = getGmailService();
            
        	System.out.println("Insert a reciever:");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String reciever = reader.readLine();
        	
            System.out.println("Insert a subject:");
            String subject = reader.readLine();
            
            System.out.println("Insert body:");
            String body = reader.readLine();

            //Key generation
            KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
			SecretKey secretKey = keyGen.generateKey();
			Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			//snimaju se bajtovi kljuca.
			JavaUtils.writeBytesToFilename(KEY_FILE, secretKey.getEncoded());
			
			// Enkripcija subject-a i body-ja
			String ciphersubjectStr = encryptSubject(subject, aesCipherEnc, secretKey);
			String ciphertextStr = encryptBody(body, aesCipherEnc, secretKey);
			System.out.println("Kriptovan subject: " + ciphersubjectStr);
			System.out.println("Kriptovan tekst: " + ciphertextStr);
			
			// Slanje maila
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, ciphertextStr);
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
	
	private static String encryptBody(String body, Cipher aesCipherEnc, SecretKey secretKey) 
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		// Kompresija i enkodovanje
		String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
		
		//inicijalizacija za sifrovanje 
		IvParameterSpec ivParameterSpec1 = IVHelper.createIV();
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec1);
		
		//snimaju se bajtovi IV-a.
		JavaUtils.writeBytesToFilename(IV1_FILE, ivParameterSpec1.getIV());
		
		//sifrovanje
		byte[] ciphertext = aesCipherEnc.doFinal(compressedBody.getBytes());
		return Base64.encodeToString(ciphertext);
	}
	
	private static String encryptSubject(String subject, Cipher aesCipherEnc, SecretKey secretKey) 
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		// Kompresija i enkodovanje
		String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
		
		//inicijalizacija za sifrovanje 
		IvParameterSpec ivParameterSpec2 = IVHelper.createIV();
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec2);
		
		//snimaju se bajtovi IV-a.
		JavaUtils.writeBytesToFilename(IV2_FILE, ivParameterSpec2.getIV());
		
		byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
		return Base64.encodeToString(ciphersubject);
	}
}
