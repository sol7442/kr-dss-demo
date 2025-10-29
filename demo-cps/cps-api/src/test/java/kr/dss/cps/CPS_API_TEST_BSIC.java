package kr.dss.cps;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.utils.Utils;
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
}
