package kr.dss.cps.api;


import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.Headers;
import retrofit2.http.POST;

public interface OcspApiService {
    @Headers({
        "Content-Type: application/ocsp-request",
        "Accept: application/ocsp-response"
    })
    @POST("/ocsp") 
    Call<ResponseBody> checkCertificateStatus(@Body RequestBody requestBody);
}
