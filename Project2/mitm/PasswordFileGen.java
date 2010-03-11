package mitm;
import java.io.File;
import java.io.ObjectOutputStream;
import java.io.FileOutputStream;
// import java.io.FileInputStream;
import javax.crypto.SealedObject;
// import javax.crypto.CipherInputStream;
// import javax.crypto.CipherOutputStream;
import javax.crypto.Cipher;
import java.util.Scanner;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import javax.crypto.Mac;
import java.io.ByteArrayOutputStream;
// import java.security.cert.Certificate;
// import java.security.KeyStore.PasswordProtection;
 
/**
This file reads in a plaintext file containing usernames and passwords and generates an encrypted file from which
any supposed attacker is checked against.
*/
public final class PasswordFileGen {

	/*
	This method outputs a random string (used for generating salts and secret salts)
	*/
	private static String randomString(String str, int len) {
		SecureRandom r = new SecureRandom();
		if (len == 0)
			return str;
		else
			return r.nextInt(2) + randomString(str,len-1);
	}

	/*
	This reads in the plaintext password file and generates a file of (usr + salt + hashed password) combinations, authenticates it with a MAC, and stores it to disk.
	*/
	public static final void createPwdFiles(File clearPassFile) {
 
		EncryptedPwdFile pwdFile = new EncryptedPwdFile();
		 
		try {

			Scanner scan = new Scanner(clearPassFile);

			while (scan.hasNextLine()){

				String usr = scan.next();
				String pwd = scan.next();
				 
				String secretSalt = randomString("",8);
				String salt = randomString("",8);
				pwdFile.addEntry(usr, pwd, salt, secretSalt);
			    
			}

		}
		catch (java.io.FileNotFoundException e) {
			System.out.println("File not found.\n Please check the path and try again");
			e.printStackTrace();
		}
		catch (java.util.NoSuchElementException e) { }
		catch (Exception e) { e.printStackTrace(); }
		 
		writeFilesToKeyStore(pwdFile, clearPassFile);
 
	}


	/*
	Creates secret key to encrypt the password file as well as stores keys to KeyStore. Produces a MAC on the password file to ensure that when it is read in again it is authentic.
	*/
 	private static void writeFilesToKeyStore(EncryptedPwdFile pwd, File f){
        
		try {

			final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
			final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
			final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "JCEKS");

			
			// Initialize Key Storage
			KeyStore ks = KeyStore.getInstance(keyStoreType);

			// Initialize Key Generator
			KeyGenerator enckeygen = KeyGenerator.getInstance("AES");

			// Load a random key to sign other keys
			//FileInputStream fin = new FileInputStream(JSSEConstants.PWD_KEYSTORE_LOCATION);
			ks.load(null, ("stanfordcs").toCharArray());

			// Generate secret keys for ciphering the pwd/salt file and secret salt file and store in ks
			SecretKey pwdSaltKey = enckeygen.generateKey();
			ks.setEntry("pwdSaltKey", new KeyStore.SecretKeyEntry(pwdSaltKey),new KeyStore.PasswordProtection("stanfordcs_pwdSaltKey".toCharArray()));

			// Initialize cipher for encryption with secret keys
			Cipher salt_cipher = Cipher.getInstance("AES/CTR/NoPadding");
			salt_cipher.init(Cipher.ENCRYPT_MODE, pwdSaltKey);

			//encrypts password file as a sealedObject
			SealedObject cipherPwd = new SealedObject(pwd, salt_cipher);

			// In order to MAC it we need the bytestream, so
			// we print it to the byte array byteCipher.
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream cipherOut = new ObjectOutputStream(baos);
			cipherOut.writeObject(cipherPwd);
			byte[] byteCipher = baos.toByteArray();
			cipherOut.close();

			// Now we create the actual file on the disk
			File finalPwdFile = new File(f + "Encrypted");
			FileOutputStream os = new FileOutputStream(finalPwdFile);

			os.write(byteCipher);
			os.flush();

			// Generate secret key for HMAC-SHA1
			KeyGenerator kg = KeyGenerator.getInstance("HMACSHA1");
			SecretKey mac_key = kg.generateKey();
			ks.setEntry("mac_key", new KeyStore.SecretKeyEntry(mac_key),
				new KeyStore.PasswordProtection(("stanfordcs_mac").toCharArray()));
			ks.store(new FileOutputStream(JSSEConstants.PWD_KEYSTORE_LOCATION),("stanfordcs").toCharArray());

			// Get instance of Mac object implementing HMAC-MD5, and initialize it with the above secret key
			Mac mac = Mac.getInstance("HMACSHA1");
			mac.init(mac_key);
			byte[] mac_code = mac.doFinal(byteCipher);
			String mac_string = new String(mac_code);

			os.write(mac_code);
			os.close();

		}
		catch (Exception e) { e.printStackTrace(); }

	}
 
 
	public static void main(String[] args) {

		String curDir = System.getProperty("user.dir");
		String curFile = curDir + "/" + args[0];
		File pwdFile = new File(curFile);
		createPwdFiles(pwdFile);

	}

}
