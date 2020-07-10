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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import com.google.api.client.repackaged.org.apache.commons.codec.binary.Base64;
import com.google.api.services.gmail.Gmail;
import com.google.api.services.gmail.model.Message;

import model.mailclient.MailBody;
import signature.SignatureManager;
import support.MailHelper;
import support.MailReader;
import util.GzipUtil;

public class ReadMailClient extends MailClient {

	public static long PAGE_SIZE = 3;
	public static boolean ONLY_FIRST_PAGE = true;
	
	public static void main(String[] args) 
			throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, 
			MessagingException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableKeyException, KeyStoreException, 
			NoSuchProviderException, CertificateException {
        // Build a new authorized API client service.
        Gmail service = getGmailService();
        ArrayList<MimeMessage> mimeMessages = new ArrayList<MimeMessage>();
        
        String user = "me";
        String query = "is:unread label:INBOX";
        
        List<Message> messages = MailReader.listMessagesMatchingQuery(service, user, query, PAGE_SIZE, ONLY_FIRST_PAGE);
        for(int i=0; i<messages.size(); i++) {
        	Message fullM = MailReader.getMessage(service, user, messages.get(i).getId());
        	
        	MimeMessage mimeMessage;
			try {
				
				mimeMessage = MailReader.getMimeMessage(service, user, fullM.getId());
				
				System.out.println("\n Message number " + i);
				System.out.println("From: " + mimeMessage.getHeader("From", null));
				System.out.println("Subject: " + mimeMessage.getSubject());
				System.out.println("Body: " + MailHelper.getText(mimeMessage));
				System.out.println("\n");
				
				mimeMessages.add(mimeMessage);
	        
			} catch (MessagingException e) {
				e.printStackTrace();
			}	
        }
        
        System.out.println("Select a message to decrypt:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	        
	    String answerStr = reader.readLine();
	    Integer answer = Integer.parseInt(answerStr);
	    
		MimeMessage chosenMessage = mimeMessages.get(answer);
	    
		//preuzimanje enkriptovane poruke
		String mailBodyCSV = MailHelper.getText(chosenMessage);
		MailBody mailBody = new MailBody(mailBodyCSV);
		byte[] encBody = mailBody.getEncMessageBytes();
		byte[] IV1 = mailBody.getIV1Bytes();
		byte[] IV2 = mailBody.getIV2Bytes();
		byte[] encSecretKey = mailBody.getEncKeyBytes();
		byte[] signature = mailBody.getSignatureBytes();
		
		//dekripcija tajnog kljuca
		SecretKey secretKey = decryptSecretKey(encSecretKey);
		
		Cipher des3CipherDec = Cipher.getInstance("DESede/CBC/PKCS5Padding");
		
		// Dekriptivanje subject-a i body-ja
		String subject = decryptSubject(des3CipherDec, secretKey, chosenMessage.getSubject(), IV1);
		String body = decryptBody(des3CipherDec, secretKey, encBody, IV2);
		
		//validacija signature-a
		SignatureManager signatureManager = new SignatureManager();
		byte[] data = body.getBytes();
		
		boolean isSignatureValid = signatureManager.verify(data, signature, getUserApublicKey());
		if (isSignatureValid) {
			System.out.println("Subject text: " + new String(subject));
			System.out.println("Body text: " + body);
		}else {
			System.out.println("Signature is not valid");
		}
		
		data = "Ovo je neki izmenjen body".getBytes();
		isSignatureValid = signatureManager.verify(data, signature, getUserApublicKey());
		System.out.println("Detektovanje neregularne poruke sa izmenjenim sadrzajem. Da li je sad potpis validan? " + isSignatureValid );
	}
	
	private static String decryptBody(Cipher des3CipherDec, SecretKey secretKey, byte[] encBody, byte[] IV2) 
			throws IOException, IllegalBlockSizeException, BadPaddingException, MessagingException, InvalidKeyException, InvalidAlgorithmParameterException {
		
		IvParameterSpec ivParameterBody = new IvParameterSpec(IV2);
		
		//Inicijalizacija za dekriptovanje
		des3CipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterBody);
		
		String receivedBodyTxt = new String(des3CipherDec.doFinal(encBody));
		String decompressedBodyText = GzipUtil.decompress(Base64.decodeBase64(receivedBodyTxt));
		return decompressedBodyText;
	}
	
	private static String decryptSubject(Cipher des3CipherDec, SecretKey secretKey, String subjectEnc, byte[] IV1) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		
		IvParameterSpec ivParameterSubject = new IvParameterSpec(IV1);
		
		//inicijalizacija za dekriptovanje
		des3CipherDec.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSubject);
		
		//dekompresovanje i dekriptovanje subject-a
		String decryptedSubjectTxt = new String(des3CipherDec.doFinal(Base64.decodeBase64(subjectEnc)));
		String decompressedSubjectTxt = GzipUtil.decompress(Base64.decodeBase64(decryptedSubjectTxt));
		return decompressedSubjectTxt;
	}
	
	private static SecretKey decryptSecretKey(byte[] encSecretKey) 
			throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, 
			IOException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException  {
		
		//kreiranje keystore instance
		KeyStore ksInstanca = KeyStore.getInstance("JKS", "SUN");
		//inicijalizacija keystore instance
		File file = new File("./data/userb.jks");
		ksInstanca.load(new FileInputStream(file), "userb".toCharArray());
		//citanje privatnog kljuca usera B
		PrivateKey prKey = (PrivateKey) ksInstanca.getKey("userb", "userb".toCharArray());
		
		Cipher rsaCipherDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipherDec.init(Cipher.DECRYPT_MODE, prKey);
		byte[] decSecretKey = rsaCipherDec.doFinal(encSecretKey);
		
		SecretKey secretKey = new SecretKeySpec(decSecretKey, "DESede");
		return secretKey;	
	}
	
	private static PublicKey getUserApublicKey() throws KeyStoreException, NoSuchProviderException, 
	NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		
		//kreiranje keystore instance
		KeyStore ksInstanca = KeyStore.getInstance("JKS", "SUN");
		//inicijalizacija keystore instance
		File file = new File("./data/userb.jks");
		ksInstanca.load(new FileInputStream(file), "userb".toCharArray());
		//citanje sertifikata iz keystore-a
		Certificate cer = ksInstanca.getCertificate("usera");
		//citanje javnog kljuca usera A iz sertifikata
		return cer.getPublicKey();
	}
}
