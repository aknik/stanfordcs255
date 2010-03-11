/**
 * CS255 Project 2
 */

package mitm;

import java.security.SecureRandom;
import java.net.*;
// import javax.net.ssl.SSLServerSocket;
import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.security.KeyStore;
import javax.crypto.SecretKey;
// import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.Mac;
import java.io.ByteArrayInputStream;



// You need to add code to do the following
// 1) use SSL sockets instead of the plain sockets provided
// 2) check user authentication
// 3) perform the given administration command

class MITMAdminServer implements Runnable
{
// 	public int acceptedConnections;
	
	
    private ServerSocket m_serverSocket;
    private Socket m_socket = null;
    private HTTPSProxyEngine m_engine;
    private PrintWriter out;
     public static final int MAC_LENGTH = 20;
    
    public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine ) //throws IOException {
	    throws IOException, java.security.GeneralSecurityException, Exception {
// 	MITMPlainSocketFactory socketFactory = new MITMPlainSocketFactory();
// 	m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
	MITMSSLSocketFactory socketFactory = new MITMSSLSocketFactory();
	m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
	m_engine = engine;
    }

    public void run() {
	System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
	while( true ) {
	    try {
		m_socket = m_serverSocket.accept();

		byte[] buffer = new byte[40960];

		Pattern userPwdPattern =
		    Pattern.compile("username:(\\S+)\\s+password:(\\S+)\\s+CRA:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");
		
		BufferedInputStream in = new BufferedInputStream(m_socket.getInputStream(),buffer.length);

		// Add a writer to the socket outputstream
		out = new PrintWriter( m_socket.getOutputStream() );

		// Read a buffer full.
		int bytesRead = in.read(buffer);

		String line =
		    bytesRead > 0 ?
		    new String(buffer, 0, bytesRead) : "";

		Matcher userPwdMatcher =
		    userPwdPattern.matcher(line);

		    // parse username and pwd
		if (userPwdMatcher.find()) {
		    String userName = userPwdMatcher.group(1);
		    String password = userPwdMatcher.group(2);
		    String CRA = userPwdMatcher.group(3);

		    // if authenticated, do the command
		    if( authUser(userName,password) ) {
			String command = userPwdMatcher.group(4);
			String commonName = userPwdMatcher.group(5);

			// Check to see if CRA is activated

			String challenge = null;

			if (CRA.equals("active")){

				// Generate random challenge
				challenge = randomString("", 16);

				// Print out the MACed challenge
				System.out.println("[AdminServer]: Sends challenge - " + challenge);

				// Send challenge
				out.println(challenge);
				out.flush();

				BufferedReader r = new BufferedReader(new InputStreamReader(m_socket.getInputStream()));

				// Read in response to challenge
				String response;
	    			response = r.readLine();

				// Compare server computed MAC on (username+password+challenge) to response
				if ( checkResponse(userName, password, challenge, response) ){
					System.out.println("[AdminServer]: Client authenticated successfully");
					doCommand( command );
				}
				else{
					System.out.println("[AdminServer]: Client denied access");
					m_socket.close();
				}	
					
			}
			else{
				doCommand( command );
			}
		    }
		    else{
			System.out.println("ERROR: INVALID USERNAME/PASSWORD! TERMINATING CONNECTION!\n");
			m_socket.close();
		    }
		}	
	    }
	    catch( InterruptedIOException e ) {
	    }
	    catch( Exception e ) {
		e.printStackTrace();
	    }
	}
    }

    /*
    This method outputs a random string (user for server challenge)
    */
    private static String randomString(String str, int len) {
	SecureRandom r = new SecureRandom();
	if (len == 0)
		return str;
	else
		return ( (char) r.nextInt(78) + 40) + randomString(str,len-1);
    }

    /*
    Authenticates user in following steps:
    1) Extracts key for encrypted password in keystore, as well as the mac key used to MAC the file.
    2) Checks MAC on file, ERROR if incorrect.
    3) Reads hashed password saved on disk.
    4) Attempts to recalculate the password hash saved on disk different secret salts by brute force.
    5) Returns true if valid password hash calculated.
    */
    private boolean authUser(String usr, String pwd) {

	// MAC-then-decrypt pwd file
	File pwdFile;
	FileInputStream fis;
	KeyStore ks;
	byte[] pwdFileByteArray, mac;
 
	try {
    
		// Read password file
		pwdFile = new File(JSSEConstants.PWD_FILE_LOCATION + "Encrypted");
		fis = new FileInputStream(pwdFile);

		// Byte arrays to extract usr/pass information and MAC key
     		pwdFileByteArray = new byte[(int) pwdFile.length() - MAC_LENGTH];
		mac = new byte[MAC_LENGTH];
        
		// Read usr/pass info and MAC key to arrays
            	fis.read(pwdFileByteArray);
            	fis.read(mac);
 
		// Open KeyStore
            	ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(JSSEConstants.PWD_KEYSTORE_LOCATION), ("stanfordcs").toCharArray());
 
            	// Make sure that the MAC is valid for the encrypted passwords file.
            	if (authFile(pwdFileByteArray, mac, ks)) {

			ObjectInputStream os;

			// Extract usr/salt/password file
                	SecretKey pwdSaltKey = (SecretKey) ks.getKey("pwdSaltKey", ("stanfordcs_pwdSaltKey").toCharArray());
         		os = new ObjectInputStream(new ByteArrayInputStream(pwdFileByteArray));
         		SealedObject encPwdFile = (SealedObject) os.readObject();
         		EncryptedPwdFile passwordFile = (EncryptedPwdFile) encPwdFile.getObject(pwdSaltKey);
			os.close();

			// Try all possible secret salt and check if one is valid
			boolean valid = false;
			for(int i=0;i<256;i++){

				String secret_salt = Integer.toBinaryString(i);
				while (secret_salt.length() < 8)
					secret_salt = "0" + secret_salt;
				valid = passwordFile.checkValidUser(usr, pwd, secret_salt);
				if (valid) break;

			}			

                	return valid;
		} 
		else {
                	System.out.println("ERROR: PASSWORD FILE HAS BEEN MODIFIED!");
                	System.exit(1);
            	}

		return true;

        } 
	catch (FileNotFoundException e) {
            	System.out.println("ERROR: Password File could not be loaded or does not exist.");
            	e.printStackTrace();
            	System.exit(1);
        } 
	catch (Exception e) {
            	e.printStackTrace();
        }

	return false;

    }


    /*
    This compares the MAC saved within the password file to the newly calculated MAC on the password file to see if the
    file has been tampared with.
    */
    private boolean authFile(byte[] pwdFile, byte[] saved_mac, KeyStore ks) {

	SecretKey MAC_key;
	Mac mac;
	byte[] calc_mac;

	try {
		// Re-calculates MAC on password file and compares to saved mac parsed out of file
		MAC_key = (SecretKey) ks.getKey("mac_key", ("stanfordcs_mac").toCharArray());
		mac = Mac.getInstance("HMACSHA1");
		mac.init(MAC_key);
		calc_mac = mac.doFinal(pwdFile);
		return Arrays.equals(saved_mac, calc_mac);
	}
	catch (Exception e) {
		System.out.println("ERROR: MAC KEY NOT FOUND!");
		e.printStackTrace();
		System.exit(1);
	}

	return false;

    }
 
    /*
    Compares clients response to challenge with servers computed version of (username+password+challenge)
    */
    private boolean checkResponse(String username, String password, String challenge, String response) {

	SecretKey MAC_key;
	Mac mac;
	byte[] calc_mac;

	try {
		// Load keystore
    		KeyStore ks = KeyStore.getInstance("JCEKS");
		ks.load(new FileInputStream(JSSEConstants.PWD_KEYSTORE_LOCATION), ("stanfordcs").toCharArray());

		// Re-calculates MAC on password file and compares to saved mac parsed out of file
		MAC_key = (SecretKey) ks.getKey("mac_key", ("stanfordcs_mac").toCharArray());
		mac = Mac.getInstance("HMACSHA1");
		mac.init(MAC_key);
		System.out.println("[AdminServer]: String to be MACed - " + username + password + challenge);
		calc_mac = mac.doFinal((username+password+challenge).getBytes());

// 		String string_calc_mac = new String(calc_mac);
// 		String string_response = new String(response);

int i = 0;
String string_calc_mac = new String();
while(i < calc_mac.length) {
// 	System.out.println("[AdminServer]:\t" + Integer.toHexString(calc_mac[i] + 128));
	string_calc_mac += Integer.toHexString(calc_mac[i] + 128);
	++i;
}

		// Print out the MACed challenge
		System.out.println("[AdminServer]:\nclient:\t" + response + "\nserver:\t" + string_calc_mac);

// int i = 0;
// System.out.println("[AdminServer]:\t" + calc_mac.length + "\t" + response.length);
// while(i < calc_mac.length) {
// System.out.println("[AdminServer]:\t" + calc_mac[i] + "\t" + response[i]);
// ++i;
// }

// int i = 0;
// while(i < calc_mac.length) {
// System.out.println("[AdminServer]:\t" + Integer.toHexString(calc_mac[i] + 128));
// ++i;
// }

		//return Arrays.equals(response, calc_mac);
		return string_calc_mac.equals(response);
	}
	catch (Exception e) {
		System.out.println("ERROR: MAC KEY NOT FOUND!");
		e.printStackTrace();
		System.exit(1);
	}

	return false;

    }

    // TODO(DONE) implement the commands
    private void doCommand( String cmd ) throws IOException {
	
	String command = cmd.toLowerCase();

	// Attacker wants to see how many requests have been proxied
	if ( command.equals("stats") ){ 
 		Scanner scan = new Scanner(new FileInputStream(JSSEConstants.STATS_FILE_LOCATION));
		String proxy_requests = scan.next();
		try {
	    		if( m_socket != null ) {
 				out.println("Number of requests that have been proxied: " + proxy_requests);
				out.flush();
			}
		}
		catch (Exception e) {
	    		e.printStackTrace();
		}	
;

	}
	// Attacker wants to close the proxy
	else if ( command.equals("shutdown") ){  
		System.out.println("SERVER SHUTTING DOWN!\n\n");
		m_socket.close();
		System.exit(1);
	}

	m_socket.close();
	
    }

}
