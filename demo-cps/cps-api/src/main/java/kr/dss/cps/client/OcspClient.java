package kr.dss.cps.client;

import java.io.IOException;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import kr.dss.cps.api.OcspApiService;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.scalars.ScalarsConverterFactory;

public class OcspClient implements OCSPSource {
    /**
	 * 
	 */
	private static final long serialVersionUID = 7554842123649170219L;

	private final OcspApiService api;
    
    private DigestAlgorithm certIDDigestAlgorithm = DigestAlgorithm.SHA1;;
    
    public OcspClient(String baseUrl) {
		OkHttpClient httpClient = new OkHttpClient.Builder().retryOnConnectionFailure(true).build();
		Retrofit retrofit = new Retrofit.Builder().baseUrl(baseUrl).client(httpClient)
				.addConverterFactory(ScalarsConverterFactory.create()).build();
        this.api = retrofit.create(OcspApiService.class);
    }
    public void setCertIDDigestAlgorithm(DigestAlgorithm algorithm) {
        this.certIDDigestAlgorithm = algorithm;
    }
	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        try {
            // (1) OCSP 요청 생성
            CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(
                    certificateToken, issuerCertificateToken, certIDDigestAlgorithm);

            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
            reqBuilder.addRequest(certId);
            OCSPReq ocspReq = reqBuilder.build();
            byte[] requestBytes = ocspReq.getEncoded();

            // (2) Retrofit으로 POST 요청 (Content-Type: application/ocsp-request)
            RequestBody body = RequestBody.create(requestBytes,MediaType.parse("application/ocsp-request")
            );

            Response<ResponseBody> response = api.checkCertificateStatus(body).execute();

            if (!response.isSuccessful() || response.body() == null) {
                throw new DSSExternalResourceException("OCSP server returned invalid HTTP response: " + response.code());
            }

            // (3) 응답 파싱 (DER → OCSPResp)
            byte[] respBytes = response.body().bytes();
            OCSPResp ocspResp = new OCSPResp(respBytes);

            OCSPRespStatus status = OCSPRespStatus.fromInt(ocspResp.getStatus());
            if (!OCSPRespStatus.SUCCESSFUL.equals(status)) {
                throw new DSSExternalResourceException("OCSP Response not successful: " + status);
            }

            Object responseObject = ocspResp.getResponseObject();
            if (!(responseObject instanceof BasicOCSPResp)) {
                throw new DSSExternalResourceException("OCSP Response is not BasicOCSPResp!");
            }

            BasicOCSPResp basicResp = (BasicOCSPResp) responseObject;

            // (4) 대상 인증서에 해당하는 SingleResp 선택
            SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(
                    basicResp, certificateToken, issuerCertificateToken);

            if (latestSingleResponse == null) {
                throw new DSSException("No matching SingleResp found for target certificate.");
            }

            // (5) DSS의 OCSPToken 객체 생성
            OCSPToken ocspToken = new OCSPToken(basicResp, latestSingleResponse,
                    certificateToken, issuerCertificateToken);
            ocspToken.setSourceURL(api.toString());
            ocspToken.setExternalOrigin(RevocationOrigin.EXTERNAL);

            return ocspToken;

        } catch (IOException | OCSPException e) {
            throw new DSSException("Error while querying OCSP responder", e);
        }
	}
}
