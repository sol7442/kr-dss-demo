package kr.dss.cps.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import kr.dss.cps.CPSException;

@Configuration
public class CPSConfig {
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	private static final Logger LOG = LoggerFactory.getLogger(CPSConfig.class);

	@Value("${cps.keystore.path:tsa-keystore.p12}")
	private String cpsKeyStorePath;

	@Value("${cps.keystore.password:changeit}")
	private String cpsKeyStorePassword;

	@Value("${cps.keystore.type:PKCS12}")
	private String cpsKeyStoreType;

	@Value("${tsa.key.alias:tsa}")
	private String tsaKeyAlias;

	@Value("${tsa.key.password:changeit}")
	private String tsaKeyPassword;

	@Value("${ocsp.key.alias:tsa}")
	private String ocspKeyAlias;

	@Value("${ocsp.key.password:changeit}")
	private String ocspKeyPassword;

	@Bean
	public KeyStore keyStore() throws IOException, KeyStoreException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException {
		File ksFile = new ClassPathResource(cpsKeyStorePath).getFile();
		KeyStore keyStore = KeyStore.getInstance(cpsKeyStoreType);
		try (FileInputStream fis = new FileInputStream(ksFile)) {
			keyStore.load(fis, cpsKeyStorePassword.toCharArray());
		}
		return keyStore;
	}
	
	@Bean
	public X509Certificate tsaCert(KeyStore keyStore) throws CPSException {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(tsaKeyAlias);
			LOG.info("Loaded TSA Certificate: {}", cert.getSubjectX500Principal());
			
			return cert;
		} catch (Exception e) {
			throw new CPSException("Unable to load TSA certificate from keystore: " + cpsKeyStorePath, e);
		}
	}

	@Bean
	public PrivateKey tsaKey(KeyStore keyStore) throws CPSException {
		try {
			PrivateKey key = (PrivateKey) keyStore.getKey(tsaKeyAlias, tsaKeyPassword.toCharArray());
			LOG.info("Loaded TSA Private Key for alias: {}", tsaKeyAlias);
			return key;
		} catch (Exception e) {
			throw new CPSException("Unable to load TSA certificate from keystore: " + cpsKeyStorePath, e);
		}
	}
	
	@Bean
	public X509Certificate ocspCert(KeyStore keyStore) throws CPSException {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(ocspKeyAlias);
			LOG.info("Loaded OCSP Certificate: {}", cert.getSubjectX500Principal());
			
			return cert;
		} catch (Exception e) {
			throw new CPSException("Unable to load OCSP certificate from keystore: " + cpsKeyStorePath, e);
		}
	}

	@Bean
	public PrivateKey ocspKey(KeyStore keyStore) throws CPSException {
		try {
			PrivateKey key = (PrivateKey) keyStore.getKey(ocspKeyAlias, ocspKeyPassword.toCharArray());
			LOG.info("Loaded OCSP Private Key for alias: {}", ocspKeyAlias);
			return key;
		} catch (Exception e) {
			throw new CPSException("Unable to load OCSP certificate from keystore: " + cpsKeyStorePath, e);
		}
	}


}
