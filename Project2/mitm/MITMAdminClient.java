/**
 * CS255 project 2
 */
package mitm;

import java.io.*;
// import java.net.*;
// import java.security.MessageDigest;
import javax.net.ssl.SSLSocket;
// import javax.net.ssl.SSLServerSocket;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import javax.crypto.Mac;


public class MITMAdminClient
{
//     private Socket m_remoteSocket;
    private SSLSocket m_remoteSocket;
    private String username;
    private String password;
    private String command;
    private String commonName = "";
    private String CRAActive = "-";
    
    public static void main( String [] args ) {
	MITMAdminClient admin = new MITMAdminClient( args );
	admin.run();
    }

     private Error printUsage() {
	System.err.println(
	    "\n" +
	    "Usage: " +
	    "\n java " + MITMAdminClient.class + " <options>" +
	    "\n" +
	    "\n Where options can include:" +
	    "\n" +
	    "\n   <-userName <type> >       " +
	    "\n   <-userPassword <pass> >   " +
	    "\n   <-cmd <shudown|stats>" +
	    "\n   [-remoteHost <host name/ip>]  Default is localhost" +
	    "\n   [-remotePort <port>]          Default is 8002" +
	    "\n"
	    );

	System.exit(1);
	return null;
    }

    private MITMAdminClient( String [] args ) {
	int remotePort = 8002;
	String remoteHost = "localhost";
		
	if( args.length < 3 )
	    throw printUsage();
	
	try {
	    for (int i=0; i<args.length; i++)
	    {
		if (args[i].equals("-remoteHost")) {
		    remoteHost = args[++i];
		} 
		else if (args[i].equals("-remotePort")) {
		    remotePort = Integer.parseInt(args[++i]);
		} 
		else if (args[i].equals("-userName")) {
		    username = args[++i];
		} 
		else if (args[i].equals("-userPassword")) {
		    password = args[++i];
		} 
		else if (args[i].equals("-cmd")) {
		    command = args[++i];
		    if( command.equals("enable") || command.equals("disable") ) {
			commonName = args[++i];
		    }
		} 
		else if (args[i].equals("-CRA")) {
		    CRAActive = args[++i];
		}
		else {
		    throw printUsage();
		}
	    }

	    // TODO(DONE BUT UNCOMMENT) upgrade this to an SSL connection
 	    MITMSSLSocketFactory myMITMSSLSocketFactory = new MITMSSLSocketFactory();
            m_remoteSocket = (SSLSocket) myMITMSSLSocketFactory.createClientSocket( remoteHost, remotePort );

	    
	}
	catch (Exception e) {
	    throw printUsage();
	}

    }
    
    public void run() 
    {
	try {
	    PrintWriter writer = new PrintWriter( m_remoteSocket.getOutputStream() );
	    if( m_remoteSocket != null ) {
		writer.println("username:"+username);
		writer.println("password:"+password);
		writer.println("CRA:"+CRAActive);
		writer.println("command:"+command);
		writer.println("CN:"+commonName);
		writer.flush();
	    }

	    // now read back any response

	    BufferedReader r = new BufferedReader(new InputStreamReader(m_remoteSocket.getInputStream()));
	    String line = null;

// 	    if( !CRAActive.equals(null) && CRAActive.equals("active") ) {
// 		if( (CRAActive.length() > 0) && (CRAActive.equals("active")) ) {


		    // This loop reads challenge
		    String challenge = null;
		    challenge = r.readLine();

		    // Print out the challenge
		    System.out.println("[AdminClient]: Received challenge - " + challenge);

		    // Compute MAC on challenge
		    SecretKey MAC_key;
		    Mac mac;
		    byte[] mac_challenge = null;
	
			try {
				// Load keystore file
				KeyStore ks = KeyStore.getInstance("JCEKS");
		    		ks.load(new FileInputStream(JSSEConstants.PWD_KEYSTORE_LOCATION), ("stanfordcs").toCharArray());

				// Re-calculates MAC on password file and compares to saved mac parsed out of file
				MAC_key = (SecretKey) ks.getKey("mac_key", ("stanfordcs_mac").toCharArray());
				mac = Mac.getInstance("HMACSHA1");
				mac.init(MAC_key);
				System.out.println("[AdminClient]: String to be MACed - " + username + password + challenge );
				mac_challenge = mac.doFinal((username+password+challenge).getBytes());
			} 
			catch (Exception e) { 
				e.printStackTrace();
			}

// 		    String MAC_challenge = new String(mac_challenge);

// int i = 0;
// System.out.println("[AdminClient]:\t" + mac_challenge.length);
// while(i < mac_challenge.length) {
// System.out.println("[AdminClient]:\t" + mac_challenge[i]);
// ++i;
// }
int i = 0;
String MAC_challenge = new String();
while(i < mac_challenge.length) {
// 	System.out.println("[AdminClient]:\t" + Integer.toHexString(mac_challenge[i] + 128));
	MAC_challenge += Integer.toHexString(mac_challenge[i] + 128);
	++i;
}

		    // Print out the MACed challenge
		    System.out.println("[AdminClient]: Computed mac on challenge - " + MAC_challenge);

		    // Send MACed (username+password+challenge) back to server
		    if( m_remoteSocket != null ) {
			writer.println(MAC_challenge);
			writer.flush();
		    }

//             }

	    // This loop extracts stats or shutdown information
	    int count = 0;
	    while ((line = r.readLine()) != null) {
		
		if (count == 0){
			System.out.println("");
		    	System.out.println("Receiving input from MITM proxy:");
		    	System.out.println("");	
		}
		System.out.println("[AdminClient]: " + line);
		count++;
	    }

	} catch (Exception e) {
	    e.printStackTrace();
	}
	System.err.println("Admin Client exited");
	System.exit(0);
    }
}
