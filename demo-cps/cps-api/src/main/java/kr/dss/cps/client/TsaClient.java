package kr.dss.cps.client;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import kr.dss.cps.api.TsaApiService;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.Response;
import retrofit2.Retrofit;
import retrofit2.converter.scalars.ScalarsConverterFactory;

public class TsaClient implements TSPSource {
	/**
	 * 
	 */
	private static final long serialVersionUID = -3070682091159487477L;

	private final TsaApiService api;

	private Collection<DigestAlgorithm> acceptedDigestAlgorithms = Arrays.asList(DigestAlgorithm.SHA224,
			DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512);

	public TsaClient(String baseUrl) {
		if (!baseUrl.endsWith("/")) {
			baseUrl += "/";
		}

		OkHttpClient httpClient = new OkHttpClient.Builder().retryOnConnectionFailure(true).build();

//		HttpLoggingInterceptor logging = new HttpLoggingInterceptor(System.out::println);
//		logging.setLevel(HttpLoggingInterceptor.Level.BODY);

		Retrofit retrofit = new Retrofit.Builder().baseUrl(baseUrl).client(httpClient)
				.addConverterFactory(ScalarsConverterFactory.create()).build();

		this.api = retrofit.create(TsaApiService.class);
	}

	@Override
	public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) throws DSSException {

		if (!acceptedDigestAlgorithms.contains(digestAlgorithm)) {
			throw new DSSException(
					String.format("DigestAlgorithm '%s' is not supported by the KeyEntityTSPSource implementation!",
							digestAlgorithm));
		}

		try {
			TimeStampRequest request = createRequest(digestAlgorithm, digest);

			RequestBody body = RequestBody.create(request.getEncoded(), MediaType.parse("application/timestamp-query"));

			Response<ResponseBody> httpResponse = this.api.requestTimestamp(body).execute();
			if (isError(httpResponse)) {
				throw new DSSException(
						String.format("Unable to generate a timestamp. Reason : %s", httpResponse.message()));
			}

			TimeStampResponse response = new TimeStampResponse(httpResponse.body().bytes());
			return getTimestampBinary(response);

		} catch (IOException | TSPException e) {
			throw new DSSException(String.format("Unable to generate a timestamp. Reason : %s", e.getMessage()), e);
		}
	}

	private TimestampBinary getTimestampBinary(TimeStampResponse response) throws IOException {
		TimeStampToken timeStampToken = response.getTimeStampToken();
		if (timeStampToken != null) {
			return new TimestampBinary(timeStampToken.getEncoded());
		} else if (response.getStatusString() != null) {
			throw new DSSException(
					String.format("Unable to generate a timestamp. Reason : %s", response.getStatusString()));
		} else {
			throw new DSSException("Unable to generate a timestamp. Response returned an empty time-stamp token.");
		}
	}

	private boolean isError(Response<ResponseBody> httpResponse) {
		return !httpResponse.isSuccessful() || httpResponse.body() == null;
	}

	protected TimeStampRequest createRequest(DigestAlgorithm digestAlgorithm, byte[] digest) {
		final TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
		requestGenerator.setCertReq(true);
		return requestGenerator.generate(getASN1ObjectIdentifier(digestAlgorithm), digest);
	}

	private ASN1ObjectIdentifier getASN1ObjectIdentifier(DigestAlgorithm digestAlgorithm) {
		return getASN1ObjectIdentifier(digestAlgorithm.getOid());
	}

	private ASN1ObjectIdentifier getASN1ObjectIdentifier(String oid) {
		return new ASN1ObjectIdentifier(oid);
	}
}
