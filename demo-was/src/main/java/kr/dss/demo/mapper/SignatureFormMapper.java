package kr.dss.demo.mapper;


import kr.dss.demo.dto.SignDocumentRequest;
import kr.dss.demo.model.SignatureDocumentForm;

import java.util.Base64;
import java.util.Date;

public class SignatureFormMapper {

    public static SignatureDocumentForm toSignatureDocumentForm(SignDocumentRequest request) {
        SignatureDocumentForm form = new SignatureDocumentForm();

        // 1. Base64 → byte[]
        byte[] documentBytes = Base64.getDecoder().decode(request.getDocumentBase64());

        String contentType;
        switch (request.getSignatureForm()) {
            case XAdES -> contentType = "application/xml";
            case CAdES -> contentType = "application/pkcs7-signature";
            case PAdES -> contentType = "application/pdf";
            case JAdES -> contentType = "application/json";
            case PKCS7 -> contentType = "application/pkcs7-mime";
            default -> contentType = "application/octet-stream"; // fallback
        }

//        // 2. byte[] → MultipartFile 변환
//        MultipartFile multipartFile = new MockMultipartFile(
//                "documentToSign",                      // 필드 이름
//                request.getFileName(),
//                contentType,// 원본 파일명 (임의 값 가능)
//                documentBytes                          // 파일 데이터
//        );

        form.setFileName(request.getFileName());
        form.setContentType(contentType);
        form.setDocumentBytes(documentBytes);

        // 3. 나머지 필드 매핑
        form.setSigningDate(new Date());
        form.setSignaturePackaging(request.getSignaturePackaging());
        form.setContainerType(request.getContainerType());
        form.setSignatureForm(request.getSignatureForm());       // AbstractSignatureForm 필드
        form.setSignatureLevel(request.getSignatureLevel());     // AbstractSignatureForm 필드
        form.setDigestAlgorithm(request.getDigestAlgorithm());   // AbstractSignatureForm 필드
        form.setSignWithExpiredCertificate(request.isSignWithExpiredCertificate());
        form.setAddContentTimestamp(request.isAddContentTimestamp());

        form.setSignatureValue(request.getSignatureValue());

        return form;
    }
}
