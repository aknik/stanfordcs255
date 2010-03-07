//Based on SnifferSSLSocketFactory.java from The Grinder distribution.
// The Grinder distribution is available at http://grinder.sourceforge.net/

package mitm;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Key;
import java.security.cert.Certificate;
// import java.security.cert.X509Certificate;
import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

// import iaik.x509.X509Certificate;
import iaik.asn1.structures.*;

import java.util.Enumeration;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.math.BigInteger;



/**
 * MITMSSLSocketFactory is used to create SSL sockets.
 *
 * This is needed because the javax.net.ssl socket factory classes don't
 * allow creation of factories with custom parameters.
 *
 */
public final class MITMSSLSocketFactory implements MITMSocketFactory
{
    final ServerSocketFactory m_serverSocketFactory;
    final SocketFactory m_clientSocketFactory;
    final SSLContext m_sslContext;

    public KeyStore ks = null;

    /*
     *
     * We can't install our own TrustManagerFactory without messing
     * with the security properties file. Hence we create our own
     * SSLContext and initialise it. Passing null as the keystore
     * parameter to SSLContext.init() results in a empty keystore
     * being used, as does passing the key manager array obtain from
     * keyManagerFactory.getInstance().getKeyManagers(). To pick up
     * the "default" keystore system properties, we have to read them
     * explicitly. UGLY, but necessary so we understand the expected
     * properties.
     *
     */

    /**
     * This constructor will create an SSL server socket factory
     * that is initialized with a fixed CA certificate
     */
    public MITMSSLSocketFactory()
	throws IOException,GeneralSecurityException
    {
	m_sslContext = SSLContext.getInstance("SSL");

	final KeyManagerFactory keyManagerFactory =
	    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

	final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
	final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
	final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

	final KeyStore keyStore;
	
	if (keyStoreFile != null) {
	    keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

////////////////////////////////////////////////////////////////////////////////////////////////////////
/*System.out.println("-----------------------------------------------------------");
// check aliases in keyStor
for( Enumeration e = keyStore.aliases() ; e.hasMoreElements() ;) {
         System.out.println(e.nextElement());
}
System.out.println("----------------------");

// check certificate for the CA (us :)
iaik.x509.X509Certificate caCert = new iaik.x509.X509Certificate( (keyStore.getCertificate("cs255")).getEncoded() );
System.out.println("Certificate for: " + caCert.getSubjectDN());
System.out.println("Certificate issued by: " + caCert.getIssuerDN());
System.out.println("The certificate is valid from " + caCert.getNotBefore() + " to " + caCert.getNotAfter());
System.out.println("Certificate SN#: " + caCert.getSerialNumber());
System.out.println("Signature algorithm: " + caCert.getSigAlgName());
System.out.println("----------------------");

// create new certificate for "mail.google.com"
// iaik.x509.X509Certificate X509cert = new iaik.x509.X509Certificate();
// GregorianCalendar date = (GregorianCalendar)Calendar.getInstance();
// X509cert.setValidNotBefore(date.getTime());
// date.add(Calendar.MONTH, 6);
// X509cert.setValidNotAfter(date.getTime());


iaik.x509.X509Certificate newCert = new iaik.x509.X509Certificate();

Name issuer = new Name();	// issuer: CN=cs255, OU=Stanford, O=EE, L=Palo Alto, S=California, C=US
issuer.addRDN(iaik.asn1.ObjectID.country, "US");
issuer.addRDN(iaik.asn1.ObjectID.locality, "Palo Alto");
issuer.addRDN(iaik.asn1.ObjectID.organization ,"EE");
issuer.addRDN(iaik.asn1.ObjectID.organizationalUnit ,"Stanford");
issuer.addRDN(iaik.asn1.ObjectID.commonName ,"cs255");
newCert.setIssuerDN(issuer);

iaik.asn1.structures.Name subject = new iaik.asn1.structures.Name();	// the subject of this certificate
subject.addRDN(iaik.asn1.ObjectID.country, "AT");
subject.addRDN(iaik.asn1.ObjectID.organization ,"IAIK");
subject.addRDN(iaik.asn1.ObjectID.commonName ,"mail.google.com");
newCert.setSubjectDN(subject);

GregorianCalendar date = (GregorianCalendar)Calendar.getInstance();	// validity dates
date.add(Calendar.MONTH, 6);
newCert.setValidNotAfter(date.getTime());
date = (GregorianCalendar)Calendar.getInstance();
date.add(Calendar.MONTH, -6);
newCert.setValidNotBefore(date.getTime());

newCert.setSerialNumber(BigInteger.valueOf(0x1234L));			// set cert Serial Number

newCert.setPublicKey(caCert.getPublicKey());				// set Public Key

PrivateKey caKey = (PrivateKey) keyStore.getKey("cs255", keyStorePassword);	// get the key of the signing authority (us :)
newCert.sign(AlgorithmID.sha1WithRSAEncryption, caKey);			// self-sign the certificate

keyStore.setCertificateEntry("mail.google.com", newCert);		// add certificate to repository

System.out.println("----------------------");

// check aliases in keyStor
for( Enumeration e = keyStore.aliases() ; e.hasMoreElements() ;) {
         System.out.println(e.nextElement());
}
System.out.println("----------------------");

// check certificate for alias
iaik.x509.X509Certificate cert2 = new iaik.x509.X509Certificate( (keyStore.getCertificate("mail.google.com")).getEncoded() );
System.out.println("Certificate for: " + cert2.getSubjectDN());
System.out.println("Certificate issued by: " + cert2.getIssuerDN());
System.out.println("The certificate is valid from " + cert2.getNotBefore() + " to " + cert2.getNotAfter());
System.out.println("Certificate SN#: " + cert2.getSerialNumber());
System.out.println("Signature algorithm: " + cert2.getSigAlgName());

System.out.println("-----------------------------------------------------------");
*/
////////////////////////////////////////////////////////////////////////////////////////////////////////

	    this.ks = keyStore;
	    
	} else {
	    keyStore = null;
	}

	keyManagerFactory.init(keyStore, keyStorePassword);

	m_sslContext.init(keyManagerFactory.getKeyManagers(),
			  new TrustManager[] { new TrustEveryone() },
			  null);

	m_clientSocketFactory = m_sslContext.getSocketFactory();
	m_serverSocketFactory = m_sslContext.getServerSocketFactory(); 
    }

    /**
     * This constructor will create an SSL server socket factory
     * that is initialized with a dynamically generated server certificate
     * that contains the specified common name.
     */
    public MITMSSLSocketFactory(String remoteCN)
	throws IOException,GeneralSecurityException, Exception
    {
	// TODO: replace this with code to generate a new
	// server certificate with common name remoteCN
// 	this();

	m_sslContext = SSLContext.getInstance("SSL");

	final KeyManagerFactory keyManagerFactory =
	    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

	final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
	final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
	final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

	final KeyStore keyStore;
	
	if (keyStoreFile != null) {
	    KeyStore keyStoreCA = KeyStore.getInstance(keyStoreType);
	    keyStoreCA.load(new FileInputStream(keyStoreFile), keyStorePassword);

	    keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);
	    keyStore.deleteEntry("cs255");
	    
	    
////////////////////////////////////////////////////////////////////////////////////////////////////////
System.out.println("-----------------------------------------------------------");
System.out.println("Remote CN: " + remoteCN);
System.out.println("----------------------");

// check aliases in keyStor
/*for( Enumeration e = keyStore.aliases() ; e.hasMoreElements() ;) {
         System.out.println(e.nextElement());
}
System.out.println("----------------------");*/

// check certificate of the CA (us :)
// iaik.x509.X509Certificate caCert = new iaik.x509.X509Certificate( (keyStore.getCertificate("cs255")).getEncoded() );
iaik.x509.X509Certificate caCert = new iaik.x509.X509Certificate( (keyStoreCA.getCertificate("cs255")).getEncoded() );
System.out.println("Certificate for: " + caCert.getSubjectDN());
System.out.println("Certificate issued by: " + caCert.getIssuerDN());
System.out.println("The certificate is valid from " + caCert.getNotBefore() + " to " + caCert.getNotAfter());
System.out.println("Certificate SN#: " + caCert.getSerialNumber());
System.out.println("Signature algorithm: " + caCert.getSigAlgName());
System.out.println("----------------------");

// create new certificate for remoteCN
iaik.x509.X509Certificate newCert = new iaik.x509.X509Certificate();

Name issuer = new Name();	// issuer: CN=cs255, OU=Stanford, O=EE, L=Palo Alto, S=California, C=US
issuer.addRDN(iaik.asn1.ObjectID.country, "US");
issuer.addRDN(iaik.asn1.ObjectID.locality, "Palo Alto");
issuer.addRDN(iaik.asn1.ObjectID.organization ,"EE");
issuer.addRDN(iaik.asn1.ObjectID.organizationalUnit ,"Stanford");
issuer.addRDN(iaik.asn1.ObjectID.commonName ,"cs255");
newCert.setIssuerDN(issuer);

iaik.asn1.structures.Name subject = new iaik.asn1.structures.Name();	// the subject of this certificate
// subject.addRDN(iaik.asn1.ObjectID.country, "AT");
// subject.addRDN(iaik.asn1.ObjectID.organization ,"IAIK");
subject.addRDN(iaik.asn1.ObjectID.commonName, remoteCN);
newCert.setSubjectDN(subject);

GregorianCalendar date = (GregorianCalendar)Calendar.getInstance();	// validity dates
date.add(Calendar.MONTH, 6);
newCert.setValidNotAfter(date.getTime());
date = (GregorianCalendar)Calendar.getInstance();
date.add(Calendar.MONTH, -6);
newCert.setValidNotBefore(date.getTime());

newCert.setSerialNumber(BigInteger.valueOf(0x1234L));			// set cert Serial Number

newCert.setPublicKey(caCert.getPublicKey());				// set Public Key

PrivateKey caSecretKey = (PrivateKey) keyStoreCA.getKey("cs255", keyStorePassword);	// get the secret key of the signing authority (us :)

newCert.sign(AlgorithmID.sha1WithRSAEncryption, caSecretKey);		// self-sign the certificate

// keyStore.setCertificateEntry(remoteCN, newCert);			// add certificate to repository: alias...

iaik.x509.X509Certificate[] chain = new iaik.x509.X509Certificate[2];	// ... and key chain
chain[0] = newCert;
chain[1] = caCert;
keyStore.setKeyEntry(remoteCN, caSecretKey, keyStorePassword, chain);

System.out.println("----------------------");

// check aliases in keyStor
for( Enumeration e = keyStore.aliases() ; e.hasMoreElements() ;) {
         System.out.println(e.nextElement());
}
System.out.println("----------------------");

// check certificate for alias
iaik.x509.X509Certificate cert2 = new iaik.x509.X509Certificate( (keyStore.getCertificate(remoteCN)).getEncoded() );
System.out.println("Certificate for: " + cert2.getSubjectDN());
System.out.println("Certificate issued by: " + cert2.getIssuerDN());
System.out.println("The certificate is valid from " + cert2.getNotBefore() + " to " + cert2.getNotAfter());
System.out.println("Certificate SN#: " + cert2.getSerialNumber());
System.out.println("Signature algorithm: " + cert2.getSigAlgName());

// caCert.checkValidity();
// cert2.checkValidity();
// newCert.verify(caCert.getPublicKey());

System.out.println("-----------------------------------------------------------");
////////////////////////////////////////////////////////////////////////////////////////////////////////

	    this.ks = keyStore;
	    
	} else {
	    keyStore = null;
	}

	keyManagerFactory.init(keyStore, keyStorePassword);
////////////////////////////////////////////////////////////////////////////////////////////////////////
System.out.println("############################  keyStore  ############################");
for( Enumeration e = keyStore.aliases() ; e.hasMoreElements() ;) {
         System.out.println(e.nextElement());
}
System.out.println("############################  this.ks  ############################");
for( Enumeration e = this.ks.aliases() ; e.hasMoreElements() ;) {
         System.out.println(e.nextElement());
}
System.out.println("#####################################################################");
////////////////////////////////////////////////////////////////////////////////////////////////////////

	m_sslContext.init(keyManagerFactory.getKeyManagers(),
			  new TrustManager[] { new TrustEveryone() },
			  null);

	m_clientSocketFactory = m_sslContext.getSocketFactory();
	m_serverSocketFactory = m_sslContext.getServerSocketFactory(); 
    }

    public final ServerSocket createServerSocket(String localHost,
						 int localPort,
						 int timeout)
	throws IOException
    {
	final SSLServerSocket socket =
	    (SSLServerSocket)m_serverSocketFactory.createServerSocket(
		localPort, 50, InetAddress.getByName(localHost));

	socket.setSoTimeout(timeout);

	socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

	return socket;
    }

    public final Socket createClientSocket(String remoteHost, int remotePort)
	throws IOException
    {
	final SSLSocket socket =
	    (SSLSocket)m_clientSocketFactory.createSocket(remoteHost,
							  remotePort);

	socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());
	
	socket.startHandshake();

	return socket;
    }

    /**
     * We're carrying out a MITM attack, we don't care whether the cert
     * chains are trusted or not ;-)
     *
     */
    private static class TrustEveryone implements X509TrustManager
    {
	public void checkClientTrusted(java.security.cert.X509Certificate[] chain,
				       String authenticationType) {
	}
	
	public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
				       String authenticationType) {
	}

// 	public iaik.x509.X509Certificate[] getAcceptedIssuers()
	public java.security.cert.X509Certificate[] getAcceptedIssuers()
	{
	    return null;
	}
    }
}
    
