/**
 * CS255 project 2
 */
/**
 * CS255 Project 2
 */

package mitm;

import java.net.*;
import javax.net.ssl.SSLServerSocket;
import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import javax.crypto.Mac;
import java.io.ByteArrayInputStream;

import javax.net.ssl.SSLServerSocket;



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
		    Pattern.compile("username:(\\S+)\\s+password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");
		
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

		    // authenticate	
		    

		    // if authenticated, do the command
		    if( authenticateUser(userName,password) ) {
			String command = userPwdMatcher.group(3);
			String commonName = userPwdMatcher.group(4);

			doCommand( command );
		    }
		    else{
			System.out.println("ERROR: INVALID USERNAME/PASSWORD! TERMINATING CONNECTION!\n\n");
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

    private boolean authenticateUser(String usr, String pwd) {

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
            	if (authenticateFile(pwdFileByteArray, mac, ks)) {

			ObjectInputStream os;

			// Extract usr/salt/password file
                	SecretKey pwdSaltKey = (SecretKey) ks.getKey("pwdSaltKey", ("stanfordcs_pwdSaltKey").toCharArray());
         		os = new ObjectInputStream(new ByteArrayInputStream(pwdFileByteArray));
         		SealedObject encPwdFile = (SealedObject) os.readObject();
         		EncryptedPwdFile passwordFile = (EncryptedPwdFile) encPwdFile.getObject(pwdSaltKey);
			os.close();

			// Extract usr/secret_salt file
			SecretKey secretSaltKey = (SecretKey) ks.getKey("secretSaltkey", ("stanfordcs_secretSaltKey").toCharArray());	
         		os = new ObjectInputStream(new FileInputStream(JSSEConstants.PWD_FILE_LOCATION + "SecretSaltEncrypted"));
         		SealedObject encSecretSaltFile = (SealedObject) os.readObject();
         		SecretSaltFile secretSaltFile = (SecretSaltFile) encSecretSaltFile.getObject(secretSaltKey);
        
                	// We know have loaded the password file, check the user and password used to start server
			// against stored usr/password information and return whether he is a fraud or not         
               		String secret_salt = secretSaltFile.get(usr);
                	return passwordFile.checkValidUser(usr, pwd, secret_salt);
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
    private boolean authenticateFile(byte[] pwdFile, byte[] saved_mac, KeyStore ks) {

	SecretKey MAC_key;
	Mac mac;
	byte[] calc_mac;

	try {
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
// 				System.out.flush();
			}
		}
		catch (Exception e) {
	    		e.printStackTrace();
		}	
// System.out.println("[AdminServer] Accepted connections: " + GlobalDataStore.acceptedConnections);

	}
	// Attacker wants to close the proxy
	else if ( command.equals("shutdown") ){  
		m_socket.close();
		System.exit(1);
	}

	m_socket.close();
	
    }

}
