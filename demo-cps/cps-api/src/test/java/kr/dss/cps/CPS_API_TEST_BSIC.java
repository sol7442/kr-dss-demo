package kr.dss.cps;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.utils.Utils;
import kr.dss.cps.client.OcspClient;
import kr.dss.cps.client.TsaClient;

public class CPS_API_TEST_BSIC {

	Logger LOG = LoggerFactory.getLogger(CPS_API_TEST_BSIC.class);

	private static final String CPS_URL = "http://localhost:8090/";

	@Test
	public void call_tsa() throws NoSuchAlgorithmException {
		TsaClient client = new TsaClient(CPS_URL);

		byte[] data = "Hello TSA".getBytes();
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(data);

        LOG.info("Request Digest : {}", Arrays.toString(digest));

		TimestampBinary tsb = client.getTimeStampResponse(DigestAlgorithm.SHA256, digest);

        assertNotNull(tsb, "TimestampBinary 객체가 null입니다.");
        assertNotNull(tsb.getBytes(), "Timestamp 응답 데이터가 비어 있습니다.");
        assertTrue(tsb.getBytes().length > 32, "Timestamp 응답 크기가 너무 작습니다.");

        final String base64EncodedTimeStampToken = Utils.toBase64(DSSASN1Utils.getDEREncoded(tsb));
        
		LOG.info("TimestampBinary : {}", base64EncodedTimeStampToken);

	}
	
	@Test
	public void call_ocsp() throws Exception {

        // 1) 테스트 인증서 로드
        X509Certificate leaf = readCert("fake_kisa_tester.cer");
        X509Certificate issuer = readCert("fake_kisa_ca.cer");

        // 2) 클라이언트 생성 및 옵션 (필요 시 SHA-1/256 설정)
        OcspClient client = new OcspClient(CPS_URL);
        client.setCertIDDigestAlgorithm(DigestAlgorithm.SHA1); // 또는 SHA256

        // 3) 호출
        OCSPToken ocspToken = client.getRevocationToken(new CertificateToken(leaf),new CertificateToken(issuer));

        // 4) 검증 (토큰/응답 기본 필드 확인)
        assertNotNull(ocspToken, "OCSPToken이 null 입니다.");
        assertNotNull(ocspToken.getBasicOCSPResp(), "BasicOCSPResp가 null 입니다.");
        assertNotNull(ocspToken.getStatus(), "Status가 null 입니다.");

        // 상태/시간 정보(있다면) 체크
        assertNotNull(ocspToken.getThisUpdate(), "thisUpdate가 null 입니다.");
        
		LOG.info("CertStatus : {}", ocspToken.getStatus());

	}
	
	private X509Certificate readCert(String cp) throws Exception {
	    // 1) 클래스패스에서 바이트 읽기
	    byte[] data;
	    try (InputStream is = getClass().getClassLoader().getResourceAsStream(cp)) {
	        assertNotNull(is, "리소스를 찾을 수 없습니다: " + cp);
	        data = is.readAllBytes();
	    }

	    CertificateFactory cf = CertificateFactory.getInstance("X.509");

	    // 2) 먼저 DER로 바로 파싱 시도 (DER 형식인 경우)
	    try (InputStream in = new ByteArrayInputStream(data)) {
	        return (X509Certificate) cf.generateCertificate(in);
	    } catch (CertificateException ignored) {
	        // 계속 진행: PEM 처리
	    }

	    // 3) PEM 처리: BEGIN/END 블록 사이의 본문만 추출
	    String text = new String(data, StandardCharsets.US_ASCII);

	    // BEGIN TRUSTED CERTIFICATE / BEGIN CERTIFICATE 모두 허용
	    Pattern pemBlock = Pattern.compile(
	        "-----BEGIN (?:TRUSTED )?CERTIFICATE-----([A-Za-z0-9+/=\\r\\n]+)-----END (?:TRUSTED )?CERTIFICATE-----",
	        Pattern.MULTILINE);
	    Matcher m = pemBlock.matcher(text);
	    if (!m.find()) {
	        throw new IllegalArgumentException("PEM CERTIFICATE 블록을 찾을 수 없습니다: " + cp);
	    }

	    // 4) 본문(Base64)만 추출 후 공백 제거 → 디코드
	    String b64 = m.group(1).replaceAll("\\s+", "");
	    byte[] der = Base64.getDecoder().decode(b64);

	    // 5) DER로 최종 파싱
	    try (InputStream in = new ByteArrayInputStream(der)) {
	        return (X509Certificate) cf.generateCertificate(in);
	    }
	}
}
