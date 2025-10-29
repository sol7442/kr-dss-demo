package kr.dss.demo.config;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.utils.Utils;
import kr.dss.cps.client.IgnoreCRLSource;
import kr.dss.cps.client.OcspClient;
import kr.dss.cps.client.TsaClient;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.security.KeyStore;

@Configuration
public class KRDSSConfig {

    private static final Logger LOG = LoggerFactory.getLogger(KRDSSConfig.class);

    @Value("${default.validation.policy}")
    private String defaultValidationPolicy;

    @Value("${dss.crl.maxNextUpdate:3600}") // 기본값 3600초
    private int crlMaxNextUpdate;

    @Value("${dss.ocsp.maxNextUpdate:3600}")
    private int ocspMaxNextUpdate;

    @Value("${dss.cache.expiration:3600}")
    private int cacheExpiration;

    @Value("${dss.http.connectionTimeout:10000}")
    private int connectionTimeout;

    @Value("${dss.http.connectionRequestTimeout:10000}")
    private int connectionRequestTimeout;

    @Value("${dss.http.redirectEnabled:true}")
    private boolean redirectEnabled;

    @Value("${dss.http.useSystemProperties:false}")
    private boolean useSystemProperties;


    @Value("${dss.truststore.filename:truststore.jks}")
    private String trustSourceKsFilename;

    @Value("${dss.truststore.type:JKS}")
    private String trustSourceKsType;

    @Value("${dss.truststore.password:changeit}")
    private String trustSourceKsPassword;

    @Value("${dss.keystore.filename:keystore.jks}")
    private String adesKeyStoreFilename;


    @Value("${dss.users.certs.type:}")
    private String userSourceType;
    @Value("${dss.users.certs.filename:}")
    private String userSourceFileName;
    @Value("${dss.users.certs.password:}")
    private String userSourcePassword;




	@Value("${cps.base.url}")
	private String cpsBaseUrl;

    @Bean
    public CertificateVerifier certificateVerifier() {
        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setCrlSource(new IgnoreCRLSource());
        certificateVerifier.setOcspSource(cachedOCSPSource());
        //certificateVerifier.setAIASource(cachedAIASource());
        certificateVerifier.setTrustedCertSources(trustedListSource(), trustedCertificateSource());

        // Default configs
        certificateVerifier.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());
        certificateVerifier.setCheckRevocationForUntrustedChains(false);
        

        return certificateVerifier;
    }

    @Bean
    public CRLSource cachedCRLSource() {
        OnlineCRLSource onlineCRLSource = onlineCRLSource();
        FileCacheDataLoader fileCacheDataLoader = initFileCacheDataLoader();
        fileCacheDataLoader.setCacheExpirationTime(crlMaxNextUpdate * 1000); // to millis
        onlineCRLSource.setDataLoader(fileCacheDataLoader);
        return onlineCRLSource;
    }
    @Bean
    public OnlineCRLSource onlineCRLSource() {
        OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
        onlineCRLSource.setDataLoader(dataLoader());
        return onlineCRLSource;
    }
    @Bean
    public OCSPSource cachedOCSPSource() {
    	OcspClient onlineOCSPSource = new OcspClient(cpsBaseUrl);
        FileCacheDataLoader fileCacheDataLoader = initFileCacheDataLoader();
        fileCacheDataLoader.setDataLoader(ocspDataLoader());
        fileCacheDataLoader.setCacheExpirationTime(ocspMaxNextUpdate * 1000); // to millis
        //onlineOCSPSource.setDataLoader(fileCacheDataLoader);
        return onlineOCSPSource;
    }
//    @Bean
//    public OnlineOCSPSource onlineOCSPSource() {
//        OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
//        onlineOCSPSource.setDataLoader(ocspDataLoader());
//        return onlineOCSPSource;
//    }
    @Bean
    public AIASource cachedAIASource() {
        FileCacheDataLoader fileCacheDataLoader = fileCacheDataLoader();
        return new DefaultAIASource(fileCacheDataLoader);
    }

    @Bean(name = "trusted-list-certificate-source")
    public TrustedListsCertificateSource trustedListSource() {
        return new TrustedListsCertificateSource();
    }

    @Bean
    public CommonTrustedCertificateSource trustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        LOG.info("TRUST FILE : {}", trustSourceKsFilename);
        if (Utils.isStringNotEmpty(trustSourceKsFilename)) {
            try {
                KeyStoreCertificateSource keyStore = new KeyStoreCertificateSource(
                        new ClassPathResource(trustSourceKsFilename).getFile(), trustSourceKsType, trustSourceKsPassword.toCharArray());
                trustedCertificateSource.importAsTrusted(keyStore);

                LOG.info("KeyStore : {}",keyStore.getEntities());
            } catch (IOException e) {
                throw new DSSException("Unable to load the file " + adesKeyStoreFilename, e);
            }
        }

        return trustedCertificateSource;
    }

    @Bean
    public CommonTrustedCertificateSource userCertificateSource() {
        CommonTrustedCertificateSource userCertificateSource = new CommonTrustedCertificateSource();
        LOG.info("TRUST FILE : {}", userSourceFileName);
        if (Utils.isStringNotEmpty(userSourceFileName)) {
            try {
                KeyStoreCertificateSource keyStore = new KeyStoreCertificateSource(
                        new ClassPathResource(userSourceFileName).getFile(), userSourceType, userSourcePassword.toCharArray());
                userCertificateSource.importAsTrusted(keyStore);

                LOG.info("KeyStore : {}",keyStore.getEntities());
            } catch (IOException e) {
                throw new DSSException("Unable to load the file " + adesKeyStoreFilename, e);
            }
        }

        return userCertificateSource;
    }

    @Bean
    public FileCacheDataLoader fileCacheDataLoader() {
        FileCacheDataLoader fileCacheDataLoader = initFileCacheDataLoader();
        fileCacheDataLoader.setCacheExpirationTime(cacheExpiration * 1000); // to millis
        return fileCacheDataLoader;
    }

    private FileCacheDataLoader initFileCacheDataLoader() {
        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setDataLoader(dataLoader());
        // Per default uses "java.io.tmpdir" property
        // fileCacheDataLoader.setFileCacheDirectory(new File("/tmp"));
        return fileCacheDataLoader;
    }

    @Bean
    public CommonsDataLoader dataLoader() {
        return configureCommonsDataLoader(new CommonsDataLoader());
    }

    @Bean
    public OCSPDataLoader ocspDataLoader() {
        return configureCommonsDataLoader(new OCSPDataLoader());
    }

    private <C extends CommonsDataLoader> C configureCommonsDataLoader(C dataLoader) {
        dataLoader.setTimeoutConnection(connectionTimeout);
        dataLoader.setTimeoutConnectionRequest(connectionRequestTimeout);
        dataLoader.setRedirectsEnabled(redirectEnabled);
        dataLoader.setUseSystemProperties(useSystemProperties);
//        dataLoader.setProxyConfig(proxyConfig);
        return dataLoader;
    }

    @Bean
    public KeyStoreSignatureTokenConnection remoteToken() throws IOException {
        return new KeyStoreSignatureTokenConnection(new ClassPathResource(userSourceFileName).getFile(), userSourceType,
                new KeyStore.PasswordProtection(userSourcePassword.toCharArray()));
    }

    @Bean
    public ClassPathResource defaultPolicy() {
        return new ClassPathResource(defaultValidationPolicy);
    }

    @Bean
    public SignaturePolicyProvider signaturePolicyProvider() {
        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        signaturePolicyProvider.setDataLoader(fileCacheDataLoader());
        return signaturePolicyProvider;
    }

    @Bean
    public TSPSource tspSource() {
    	LOG.info("Initializing TSPSource with CPS Base URL: {}", cpsBaseUrl);
    	return new TsaClient(cpsBaseUrl);
    }
//    @Bean
//    public OCSPSource ocspSource() {
//    	LOG.info("Initializing TSPSource with CPS Base URL: {}", cpsBaseUrl);
//    	return new OcspClient(cpsBaseUrl);
//    }
}
