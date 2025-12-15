package kr.dss.cps.services;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;

@Service
public class OCSPService {
	private static final Logger LOG = LoggerFactory.getLogger(OCSPService.class);

	private final X509Certificate issuerCert;
	private final X509Certificate ocspCert;
	private final PrivateKey ocspKey;

	//2025.11.19
	private final X509CRL crl;

	@Autowired
	public OCSPService(@Qualifier("issuerCert") X509Certificate issuerCert,
                       @Qualifier("ocspCert") X509Certificate ocspCert, @Qualifier("ocspKey") PrivateKey ocspKey, X509CRL crl) {
		this.issuerCert = issuerCert;
		this.ocspCert = ocspCert;
		this.ocspKey = ocspKey;
        this.crl = crl;
    }

	@PostConstruct
	private void init() {
		Security.addProvider(new BouncyCastleProvider());
		LOG.info("OCSPService initialized with issuer={}, ocsp={}", issuerCert.getSubjectX500Principal(),
				ocspCert.getSubjectX500Principal());
	}

	public byte[] generateOcspResponse(byte[] requestBytes) {
		try {
			OCSPReq ocspReq = new OCSPReq(requestBytes);
			LOG.info("Received OCSP request with {} certificate(s)", ocspReq.getRequestList().length);

			// ResponderID 생성
//			X500Name responderName = new X500Name(ocspCert.getSubjectX500Principal().getName());
//			RespID responderId = new RespID(responderName);
//			BasicOCSPRespBuilder respBuilder = new BasicOCSPRespBuilder(responderId);

			//2025.11.18_sujin : subjectName 대신 key_hash값으로 responsderId 변경
			SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(ocspCert.getPublicKey().getEncoded());
			DigestCalculatorProvider digCalcProv = new BcDigestCalculatorProvider();
			DigestCalculator digCalc = digCalcProv.get(CertificateID.HASH_SHA1);
			BasicOCSPRespBuilder respBuilder = new BasicOCSPRespBuilder(keyInfo, digCalc);

			Extension nonceExt = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			LOG.debug("OCSP Extension  {} ",nonceExt);
			if (nonceExt != null) {
				LOG.debug("OCSP request contains nonce extension.");
				// 응답에 동일한 nonce를 반영
				Extensions respExts = new Extensions(nonceExt);
				respBuilder.setResponseExtensions(respExts);
			}

			// 각 요청 항목에 대해 GOOD 상태 응답
			Date thisUpdate = new Date();
			Date nextUpdate = new Date(thisUpdate.getTime() + (12 * 60 * 60 * 1000L)); // 12시간 instead of 24h

			for (Req req : ocspReq.getRequestList()) {
				CertificateID certId = req.getCertID();
				LOG.debug("CertID serial={} hashAlg={}", certId.getSerialNumber(), certId.getHashAlgOID());
				respBuilder.addResponse(certId, CertificateStatus.GOOD, thisUpdate, nextUpdate, null);
			}

			// OCSP 응답 서명자
			ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(ocspKey);

			// 체인
			X509CertificateHolder[] chain = new X509CertificateHolder[] { new JcaX509CertificateHolder(ocspCert) };

			BasicOCSPResp basicResp = respBuilder.build(signer, chain, new Date());

			OCSPResp ocspResponse = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp);

			LOG.info("Generated OCSP response SUCCESSFULLY ({} certs)", ocspReq.getRequestList().length);
			return ocspResponse.getEncoded();

		} catch (IOException | OperatorCreationException | OCSPException | CertificateEncodingException e) {
			LOG.error("OCSP response generation failed", e);
			throw new RuntimeException("OCSP Response generation failed: " + e.getMessage(), e);
		}
	}
	public byte[] searchCRL() throws CRLException {
		byte[] crlBytes = crl.getEncoded();
		LOG.info("CRL encoded length: {}", crlBytes.length);
		return crlBytes;
	}

}
