package kr.dss.cps.api;


import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.Headers;
import retrofit2.http.POST;

public interface TsaApiService {
    @Headers({
        "Content-Type: application/timestamp-query",
        "Accept: application/timestamp-reply"
    })
    @POST("/tsa") 
    Call<ResponseBody> requestTimestamp(@Body RequestBody  requestBody);
}
