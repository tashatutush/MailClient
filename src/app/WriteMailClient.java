package app;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.internet.MimeMessage;

import com.google.api.services.gmail.Gmail;

import model.mailclient.MailBody;
import util.Base64;
import util.GzipUtil;
import util.IVHelper;
import support.MailHelper;
import support.MailWritter;

public class WriteMailClient extends MailClient {
	
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
			
			// kreiranje inicijalizacionih vektora
			IvParameterSpec ivParameterSubject = IVHelper.createIV();
			IvParameterSpec ivParameterBody = IVHelper.createIV();
			
			// Enkripcija subject-a i body-ja
			String ciphersubjectStr = encryptSubject(ivParameterSubject, subject, aesCipherEnc, secretKey);
			byte[] ciphertext = encryptBody(ivParameterBody, body, aesCipherEnc, secretKey);
			
			//dobavljanje javnog kljuca usera B
			PublicKey userBpublicKey = getUserBpublicKey();
			
			//ENKRIPCIJA TAJNOG KLJUCA RSA algoritmom sa javnim kljucem user-a B
			//inicijalizacija
			Cipher rsaCipherEnc = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCipherEnc.init(Cipher.ENCRYPT_MODE, userBpublicKey);
			//enkripcija
			byte [] encSecretKey = rsaCipherEnc.doFinal(secretKey.getEncoded());

			// Priprema maila
			MailBody mailBody = new MailBody(ciphertext, ivParameterSubject.getIV(), ivParameterBody.getIV(), encSecretKey);
			String mailBodyCSV = mailBody.toCSV();
        	MimeMessage mimeMessage = MailHelper.createMimeMessage(reciever, ciphersubjectStr, mailBodyCSV);
        	
			//slanje maila
        	MailWritter.sendMessage(service, "me", mimeMessage);
        	
        }catch (Exception e) {
        	e.printStackTrace();
		}
	}
	
	private static byte[] encryptBody(IvParameterSpec ivParameterBody, String body, Cipher aesCipherEnc, SecretKey secretKey) 
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		// Kompresija i enkodovanje
		String compressedBody = Base64.encodeToString(GzipUtil.compress(body));
		
		//inicijalizacija za sifrovanje 
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterBody);
		
		//sifrovanje
		return aesCipherEnc.doFinal(compressedBody.getBytes());

	}
	
	private static String encryptSubject(IvParameterSpec ivParameterSubject, String subject, Cipher aesCipherEnc, SecretKey secretKey) 
			throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		// Kompresija i enkodovanje
		String compressedSubject = Base64.encodeToString(GzipUtil.compress(subject));
		
		//inicijalizacija za sifrovanje 
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSubject);
		
		byte[] ciphersubject = aesCipherEnc.doFinal(compressedSubject.getBytes());
		return Base64.encodeToString(ciphersubject);
	}
	
	private static PublicKey getUserBpublicKey() throws KeyStoreException, NoSuchProviderException, 
	NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		
		//kreiranje keystore instance
		KeyStore ksInstanca = KeyStore.getInstance("JKS", "SUN");
		//inicijalizacija keystore instance
		File file = new File("./data/usera.jks");
		ksInstanca.load(new FileInputStream(file), "usera".toCharArray());
		//citanje sertifikata iz keystore-a
		Certificate cer = ksInstanca.getCertificate("userb");
		//citanje javnog kljuca usera B iz sertifikata
		return cer.getPublicKey();
	}
}
