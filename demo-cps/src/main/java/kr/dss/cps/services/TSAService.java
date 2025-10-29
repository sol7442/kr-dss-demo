package kr.dss.cps.services;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

@Service
public class TSAService {
	private final SecureRandom random = new SecureRandom();

	private final X509Certificate tsaCert;
	private final PrivateKey tsaKey;

    @Autowired
    public TSAService(@Qualifier("tsaKey") PrivateKey tsaKey,
                      @Qualifier("tsaCert") X509Certificate tsaCert) {
        this.tsaKey = tsaKey;
        this.tsaCert = tsaCert;
    }
    
	public byte[] generateTimestampResponse(byte[] requestBytes)
			throws IOException, OperatorCreationException, TSPException, CertificateEncodingException {
		TimeStampRequest request = new TimeStampRequest(requestBytes);

		// 응답용 생성기 초기화
		String sigAlgo = tsaKey.getAlgorithm().equalsIgnoreCase("RSA") ? "SHA256withRSA" : "SHA256withECDSA";

		TimeStampTokenGenerator tokenGenerator = createTokenGenerator(sigAlgo);

		// 응답 생성
		BigInteger serialNumber = new BigInteger(64, random);
		Date genTime = new Date();
		TimeStampResponseGenerator responseGenerator = new TimeStampResponseGenerator(tokenGenerator,
				TSPAlgorithms.ALLOWED);

		TimeStampResponse response = responseGenerator.generate(request, serialNumber, genTime);

		return response.getEncoded();
	}

	private TimeStampTokenGenerator createTokenGenerator(String sigAlgo) throws OperatorCreationException, TSPException, CertificateEncodingException{
		ContentSigner contentSigner = new JcaContentSignerBuilder(sigAlgo).setProvider("BC").build(tsaKey);

		SignerInfoGenerator signerInfoGen = new JcaSignerInfoGeneratorBuilder(new BcDigestCalculatorProvider())
				.build(contentSigner, tsaCert);

		// Digest 계산기 (TSTInfo 생성 시 사용)
		DigestCalculator digestCalculator = new BcDigestCalculatorProvider()
				.get(new AlgorithmIdentifier(TSPAlgorithms.SHA256));

		// TSA 정책 OID — 실제 TSA 정책으로 교체 가능
		ASN1ObjectIdentifier tsaPolicy = new ASN1ObjectIdentifier("1.2.3.4.1");

		// issuerSerialIncluded = true → 서명자 식별자에 Issuer/Serial 포함
		return new TimeStampTokenGenerator(signerInfoGen, digestCalculator, tsaPolicy, true);
	}

}
