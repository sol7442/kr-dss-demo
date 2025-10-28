package kr.dss.demo.mapper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.dss.demo.controller.SignatureController;
import kr.dss.demo.dto.VerifySignedDocRequest;
import kr.dss.demo.model.OriginalFile;
import kr.dss.demo.model.ValidationForm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import java.util.Base64;
import java.util.List;


public class ValidationFormMapper {
    private static final Logger LOG = LoggerFactory.getLogger(SignatureController.class);


    //Detached, Enveloped ok
    public static ValidationForm toVerifyDocumentForm(VerifySignedDocRequest request) throws JsonProcessingException {
        ValidationForm form = new ValidationForm();

        //1. Base64 -> byte[]
        LOG.info("toVerifyDocumentForm ... ");

        byte[] signatureBytes = Base64.getDecoder().decode(request.getSignature());
        byte[] documentBytes = null;
        if (request.getDocument() != null) {
            documentBytes =  Base64.getDecoder().decode(request.getDocument());
        }
        VerifySignedDocRequest.PolicyProperties policyProperties = request.getPolicy();

        // 2. byte[] -> MultipartFile
        LOG.info("before byte[] to MultipartFile (original) ... ");

        //2025.10.27_sujin : 파일명 수정 필요
        MultipartFile original = new MockMultipartFile(
                "documentBase64",
                "fileName",
                null,
                documentBytes
        );
        LOG.info("original(MultipartFile) : {}", original);

        LOG.info("before byte[] to MultipartFile (signature) ... ");
        MultipartFile signatures = new MockMultipartFile(
                "signatureBase64",
                "fileName",
                null,
                signatureBytes
        );

        LOG.info("before byte[] to MultipartFile (policy) ... ");
        ObjectMapper objectMapper = new ObjectMapper();
        byte[] jsonBytes = objectMapper.writeValueAsBytes(policyProperties);
        MultipartFile policies = new MockMultipartFile(
                "policy",
                "fileName",
                MediaType.APPLICATION_JSON_VALUE,
                jsonBytes
        );

        // ------------------------------
        //2. set variables
        LOG.info("set variables ...");
        form.setSignedFile(signatures);

        OriginalFile originalFile = new OriginalFile();
        originalFile.setCompleteFile(original);
        form.setOriginalFiles(List.of(originalFile)); //List<OriginalFile> original;
        form.setPolicyFile(policies);
        // ------------------------------

        return form;
    }
}
