package kr.dss.demo.controller;

import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import jakarta.validation.Valid;
import kr.dss.demo.dto.SignDocumentRequest;
import kr.dss.demo.dto.SignDocumentResponse;
import kr.dss.demo.dto.VerifySignedDocRequest;
import kr.dss.demo.mapper.SignatureFormMapper;
import kr.dss.demo.model.SignatureDocumentForm;
import kr.dss.demo.services.SigningService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.util.Base64;


@Controller
@SessionAttributes(value = { "signatureDocumentForm", "signedDocument" })
@RequestMapping(value = "/kr-dss")
public class SignatureController extends AbstractSignatureController{
    private static final Logger LOG = LoggerFactory.getLogger(SignatureController.class);

    private static final String SIGNATURE_PARAMETERS = "signature";

    private static final String[] ALLOWED_FIELDS = { "documentToSign", "containerType", "signatureForm", "signaturePackaging",
            "signatureLevel", "digestAlgorithm", "signWithExpiredCertificate", "addContentTimestamp" };


    @Autowired
    private SigningService signingService;




    @RequestMapping(value = "/sign-document", method = RequestMethod.POST)
    @ResponseBody
    public SignDocumentResponse signDocument(
            @Valid @RequestBody SignDocumentRequest signDocumentRequest
    ) {
        LOG.info("request : {}", signDocumentRequest.toString());

        SignDocumentResponse signDocumentResponse = new SignDocumentResponse();

        try {

            SignatureDocumentForm form = SignatureFormMapper.toSignatureDocumentForm(signDocumentRequest);


            DSSDocument document = signingService.signDocument(form);
            String base64Document  = Base64.getEncoder().encodeToString(DSSUtils.toByteArray(document));

            signDocumentResponse.setFileName(document.getName());
            signDocumentResponse.setDocumentBase64(base64Document);

            signDocumentResponse.setResult("SUCCESS");
            return signDocumentResponse;
        } catch (Exception e) {
            return new SignDocumentResponse(e.getMessage());
        }
    }

    @RequestMapping(value = "/verify-signature", method = RequestMethod.POST)
    @ResponseBody
    public SignDocumentResponse verifySignature(
            @Valid @RequestBody VerifySignedDocRequest verifySignedDocRequest
    ) {
        LOG.info("request : {}", verifySignedDocRequest.toString());

        return new SignDocumentResponse("SUCCESS");
    }
}
