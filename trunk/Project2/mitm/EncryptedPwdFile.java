package mitm;
 
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.io.Serializable;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Iterator;

/**
Generates an encrypted password file.
*/ 
public class EncryptedPwdFile implements Serializable{

	HashMap<String, SaltPlusHashedPwd> PASS_MAP;
	private int NUM_HASHES = 100;

	/*
	SaltPlusHashedPwd is struct equivalent in java. Creates object that wraps users salt and password.
	*/
	private class SaltPlusHashedPwd implements Serializable{

		String salt;
		byte[] pwd;
		 
		private SaltPlusHashedPwd(String s, byte[] p) {
			this.salt = s;
			this.pwd = p;
		}
	 
	}

	/*
	Constructor for EncryptedPwdFile. Creates a new hashmap that stores all users and their corresponding passwords and 		salts. Also sets up hash function with MD5 scheme.
	*/
	protected EncryptedPwdFile() {
	 
		PASS_MAP = new HashMap<String, SaltPlusHashedPwd>();
	 
	}
	 
	/*
	This method takes a usr and hashes his password with a randomly generated salt + secretsalt and places into 		PASS_MAP.
	*/
	protected void addEntry(String usr, String pwd, String salt, String secretSalt) {

		byte[] password;
		try {
			int i=0;
			MessageDigest md = MessageDigest.getInstance("MD5");
			while (i<(NUM_HASHES-1)){
				md.update((pwd + salt + secretSalt).getBytes());
				password = md.digest();
				i++;
			}
			md.update((pwd + salt + secretSalt).getBytes());
			password = md.digest();
			PASS_MAP.put(usr, new SaltPlusHashedPwd(salt, password));
		} 
		catch (Exception e) {
		        e.printStackTrace();
		}

	}

	/*
	This method checks to see if claimed user is valid, performs hash on password and secret salt and compares to 		stored value in file.
	*/
	public boolean checkValidUser(String usr, String pwd, String secretSalt) {

		SaltPlusHashedPwd saltHashedPwd;
		byte[] pwdCompare;
	
		try {
			int i=0;
			MessageDigest md = MessageDigest.getInstance("MD5");
			saltHashedPwd = PASS_MAP.get(usr);
			while (i<(NUM_HASHES-1)){
				md.update((pwd + saltHashedPwd.salt + secretSalt).getBytes());
				pwdCompare = md.digest();
				i++;
			}
			md.update((pwd + saltHashedPwd.salt + secretSalt).getBytes());;
			pwdCompare = md.digest();
			return Arrays.equals(saltHashedPwd.pwd, pwdCompare);
		} 
		catch (Exception e) { 
			return false;
		}

	}

	/*
	Prints the contents of PASS_MAP in string format, this includes all (usr + salt + hashed password) combinations.
	*/
	public String toString() {

		String str = "";
		String usr;
		SaltPlusHashedPwd saltHashedPwd;

		for (Map.Entry<String, SaltPlusHashedPwd> entry : PASS_MAP.entrySet()) {
    			usr = entry.getKey();
    			saltHashedPwd = entry.getValue();
			try {
			    	str += "User " + usr + " has salt " + saltHashedPwd.salt + " and password " + saltHashedPwd.pwd + "\n";
			} 
			catch (Exception e) {
				e.printStackTrace();
			}

		}
		return str;

	}

}
