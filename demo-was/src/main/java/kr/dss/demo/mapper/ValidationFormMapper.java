package kr.dss.demo.mapper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.ValidationLevel;
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
import java.util.Date;
import java.util.List;
import java.util.Map;


public class ValidationFormMapper {
    private static final Logger LOG = LoggerFactory.getLogger(ValidationFormMapper.class);

    private static final Map<SignatureLevel, ValidationLevel> LEVEL_MAPPING =
            Map.ofEntries(
                    // XAdES
                    Map.entry(SignatureLevel.XAdES_BASELINE_B,  ValidationLevel.BASIC_SIGNATURES),
                    Map.entry(SignatureLevel.XAdES_BASELINE_T,  ValidationLevel.TIMESTAMPS),
                    Map.entry(SignatureLevel.XAdES_BASELINE_LT, ValidationLevel.LONG_TERM_DATA),
                    Map.entry(SignatureLevel.XAdES_BASELINE_LTA,ValidationLevel.ARCHIVAL_DATA),

                    // CAdES
                    Map.entry(SignatureLevel.CAdES_BASELINE_B,  ValidationLevel.BASIC_SIGNATURES),
                    Map.entry(SignatureLevel.CAdES_BASELINE_T,  ValidationLevel.TIMESTAMPS),
                    Map.entry(SignatureLevel.CAdES_BASELINE_LT, ValidationLevel.LONG_TERM_DATA),
                    Map.entry(SignatureLevel.CAdES_BASELINE_LTA,ValidationLevel.ARCHIVAL_DATA),

                    // PAdES
                    Map.entry(SignatureLevel.PAdES_BASELINE_B,  ValidationLevel.BASIC_SIGNATURES),
                    Map.entry(SignatureLevel.PAdES_BASELINE_T,  ValidationLevel.TIMESTAMPS),
                    Map.entry(SignatureLevel.PAdES_BASELINE_LT, ValidationLevel.LONG_TERM_DATA),
                    Map.entry(SignatureLevel.PAdES_BASELINE_LTA,ValidationLevel.ARCHIVAL_DATA),

                    // JAdES
                    Map.entry(SignatureLevel.JAdES_BASELINE_B,  ValidationLevel.BASIC_SIGNATURES),
                    Map.entry(SignatureLevel.JAdES_BASELINE_T,  ValidationLevel.TIMESTAMPS),
                    Map.entry(SignatureLevel.JAdES_BASELINE_LT, ValidationLevel.LONG_TERM_DATA),
                    Map.entry(SignatureLevel.JAdES_BASELINE_LTA,ValidationLevel.ARCHIVAL_DATA)
            );

    //Detached, Enveloped ok
    public static ValidationForm toVerifyDocumentForm(VerifySignedDocRequest request) throws JsonProcessingException {
        ValidationForm form = new ValidationForm();

        //1. Base64 -> byte[]
//        LOG.info("toVerifyDocumentForm ... ");
        byte[] signatureBytes = Base64.getDecoder().decode(request.getSignature());
        byte[] documentBytes = null;
        if (request.getDocument() != null) {
            documentBytes =  Base64.getDecoder().decode(request.getDocument());
        }

//        VerifySignedDocRequest.PolicyProperties policyProperties = request.getPolicy();

        // 2. byte[] -> MultipartFile
        MultipartFile original = new MockMultipartFile(
                "documentBase64",
                "originalFile",
                null,
                documentBytes
        );

        MultipartFile signatures = new MockMultipartFile(
                "signatureBase64",
                "signatureFile",
                null,
                signatureBytes
        );

        /*
        MultipartFile policies = null;
        if (policyProperties.getPolicyFile()!=null) {
            LOG.info("before byte[] to MultipartFile (policy) ... ");
            ObjectMapper objectMapper = new ObjectMapper();
            byte[] jsonBytes = objectMapper.writeValueAsBytes(policyProperties.getPolicyFile());
            policies = new MockMultipartFile(
                    "policy",
                    "policyFile",
                    MediaType.APPLICATION_JSON_VALUE,
                    jsonBytes
            );
        }
         */

        // ------------------------------
        //2. set variables
        LOG.info("set variables ...");
        form.setSignedFile(signatures);

        OriginalFile originalFile = new OriginalFile();
        originalFile.setCompleteFile(original);
        form.setOriginalFiles(List.of(originalFile));

        //if policyFile is null, then set defaultPolicy.
        form.setDefaultPolicy(true);
        //else then set policyFile that inputFile(policyProperties.policyFile).
        /*
        if (policyProperties.getPolicyFile()==null) {
            form.setDefaultPolicy(true);
        } else {
            form.setPolicyFile(policies);
        }
         */

        ValidationLevel validationLevel = LEVEL_MAPPING.get(request.getSignatureLevel());
        form.setValidationLevel(validationLevel);
//        Date valideTime = new Date();
//        form.setValidationTime();

        return form;
    }
}

