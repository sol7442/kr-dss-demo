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
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
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
import org.springframework.core.io.Resource;

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

	@Value("${issuer.key.alias:tsa}")
	private String issuerKeyAlias;

	@Value("${crl.path:crl}")
	private String crlPath;
	
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
	
	
	
	
	@Bean(name = "issuerCert")
	public X509Certificate issuerCert(KeyStore keyStore) throws CPSException {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(issuerKeyAlias);
			LOG.info("Loaded issuer Certificate: {}", cert.getSubjectX500Principal());
			
			return cert;
		} catch (Exception e) {
			throw new CPSException("Unable to load TSA certificate from keystore: " + cpsKeyStorePath, e);
		}
	}	
	
	@Bean(name = "tsaCert")
	public X509Certificate tsaCert(KeyStore keyStore) throws CPSException {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(tsaKeyAlias);
			LOG.info("Loaded TSA Certificate: {}", cert.getSubjectX500Principal());
			
			return cert;
		} catch (Exception e) {
			throw new CPSException("Unable to load TSA certificate from keystore: " + cpsKeyStorePath, e);
		}
	}

	@Bean(name = "tsaKey")
	public PrivateKey tsaKey(KeyStore keyStore) throws CPSException {
		try {
			PrivateKey key = (PrivateKey) keyStore.getKey(tsaKeyAlias, tsaKeyPassword.toCharArray());
			LOG.info("Loaded TSA Private Key for alias: {}", tsaKeyAlias);
			return key;
		} catch (Exception e) {
			throw new CPSException("Unable to load TSA certificate from keystore: " + cpsKeyStorePath, e);
		}
	}
	
	@Bean(name = "ocspCert")
	public X509Certificate ocspCert(KeyStore keyStore) throws CPSException {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(ocspKeyAlias);
			LOG.info("Loaded OCSP Certificate: {}", cert.getSubjectX500Principal());
			
			return cert;
		} catch (Exception e) {
			throw new CPSException("Unable to load OCSP certificate from keystore: " + cpsKeyStorePath, e);
		}
	}

	@Bean(name = "ocspKey")
	public PrivateKey ocspKey(KeyStore keyStore) throws CPSException {
		try {
			PrivateKey key = (PrivateKey) keyStore.getKey(ocspKeyAlias, ocspKeyPassword.toCharArray());
			LOG.info("Loaded OCSP Private Key for alias: {}", ocspKeyAlias);
			return key;
		} catch (Exception e) {
			throw new CPSException("Unable to load OCSP certificate from keystore: " + cpsKeyStorePath, e);
		}
	}

	@Bean(name = "crl")
	public X509CRL crl() throws CPSException {
		try {
			// 1) CRL 파일 경로 또는 classpath 기반 (필요하면 외부에서 주입 가능)
			// 예: "classpath:crl/rootca.crl"
			Resource resource = new ClassPathResource(crlPath);

//			if (!resource.exists()) {
//				throw new CPSException("CRL file not found at path: " + resource.getDescription());
//			}

			// 2) CRL 파싱
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) certFactory.generateCRL(resource.getInputStream());

			LOG.info("Loaded CRL: issuer={}, thisUpdate={}, nextUpdate={}",
					crl.getIssuerX500Principal(),
					crl.getThisUpdate(),
					crl.getNextUpdate());

			return crl;

		} catch (Exception e) {
			throw new CPSException("Failed to load CRL file: " + e.getMessage(), e);
		}
	}
}
