package eu.europa.esig.dss.web.controller;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.web.WebAppUtils;
import eu.europa.esig.dss.web.dto.SignDocumentRequest;
import eu.europa.esig.dss.web.dto.SignDocumentResponse;
import eu.europa.esig.dss.web.editor.ASiCContainerTypePropertyEditor;
import eu.europa.esig.dss.web.editor.EnumPropertyEditor;
import groovy.util.logging.Slf4j;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.util.Date;
import java.util.List;

@Controller
@SessionAttributes(value = { "signatureDocumentForm", "signedDocument" })
@RequestMapping(value = "/kr-dss")
public class KR_SignatureController extends AbstractSignatureController {

	private static final Logger LOG = LoggerFactory.getLogger(KR_SignatureController.class);

	private static final String SIGNATURE_PARAMETERS = "signature";
	
	private static final String[] ALLOWED_FIELDS = { "documentToSign", "containerType", "signatureForm", "signaturePackaging",
			"signatureLevel", "digestAlgorithm", "signWithExpiredCertificate", "addContentTimestamp" };


	@RequestMapping(value = "/sign-document", method = RequestMethod.POST)
	@ResponseBody
	public SignDocumentResponse signDocument(
			@Valid SignDocumentRequest signDocumentRequest
			) {

		LOG.debug("request : \n",signDocumentRequest);

		SignDocumentResponse signedDocumentResponse = new SignDocumentResponse();
//		signatureDocumentForm.setSignatureValue(signatureValue.getSignatureValue());
//
//		DSSDocument document = signingService.signDocument(signatureDocumentForm);
//		InMemoryDocument signedDocument = new InMemoryDocument(DSSUtils.toByteArray(document), document.getName(), document.getMimeType());
//		//model.addAttribute("signedDocument", signedDocument);
//
//		SignDocumentResponse signedDocumentResponse = new SignDocumentResponse();
//		signedDocumentResponse.setUrlToDownload("download");
		return signedDocumentResponse;
	}
	@RequestMapping(value = "/getSignDocument", method = RequestMethod.GET)
	@ResponseBody
	public SignDocumentResponse getSignDocument(
	) {

		LOG.info("request -----: \n","getSignDocument");

		SignDocumentResponse signedDocumentResponse = new SignDocumentResponse();

//
//		DSSDocument document = signingService.signDocument(signatureDocumentForm);
//		InMemoryDocument signedDocument = new InMemoryDocument(DSSUtils.toByteArray(document), document.getName(), document.getMimeType());
//		//model.addAttribute("signedDocument", signedDocument);
//
//		SignDocumentResponse signedDocumentResponse = new SignDocumentResponse();
//		signedDocumentResponse.setUrlToDownload("download");
		return signedDocumentResponse;
	}
}
