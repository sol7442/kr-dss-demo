package kr.dss.demo.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.OriginalIdentifierProvider;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.identifier.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;
import jakarta.xml.soap.Detail;
import kr.dss.demo.WebAppUtils;
import kr.dss.demo.dto.VerifySignedDocRequest;
import kr.dss.demo.dto.VerifySignedDocResponse;
import kr.dss.demo.editor.EnumPropertyEditor;
import kr.dss.demo.exception.InternalServerException;
import kr.dss.demo.exception.SourceNotFoundException;
import kr.dss.demo.mapper.ValidationFormMapper;
import kr.dss.demo.model.ValidationForm;
import kr.dss.demo.services.FOPService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;

@Controller
@SessionAttributes(value={"ValidationForm"})
@RequestMapping(value = "/kr-dss")
public class ValidationController extends AbstractValidationController {
	private static final Logger LOG = LoggerFactory.getLogger(ValidationController.class);

	private static final String VALIDATION_TILE = "validation";
	private static final String VALIDATION_RESULT_TILE = "validation-result";

	private static final String[] ALLOWED_FIELDS = { "signedFile", "originalFiles[*].*", "digestToSend", "validationTime",
			"validationLevel", "timezoneDifference", "defaultPolicy", "policyFile", "cryptographicSuite", "signingCertificate",
			"adjunctCertificates", "evidenceRecordFiles", "includeCertificateTokens", "includeTimestampTokens", "includeRevocationTokens",
			"includeUserFriendlyIdentifiers", "includeSemantics" };

	@Autowired
	private FOPService fopService;

	@Autowired
	private Resource defaultPolicy;
//	private boolean defaultPolicy;

	@Autowired
	private CommonTrustedCertificateSource userCertificateSource;

	@Autowired
	protected SignaturePolicyProvider signaturePolicyProvider;

	@InitBinder
	public void initBinder(WebDataBinder webDataBinder) {
		super.initBinder(webDataBinder);
		webDataBinder.registerCustomEditor(ValidationLevel.class, new EnumPropertyEditor(ValidationLevel.class));
	}

	@InitBinder
	public void setAllowedFields(WebDataBinder webDataBinder) {
		webDataBinder.setAllowedFields(ALLOWED_FIELDS);
	}

	@RequestMapping(method = RequestMethod.GET)
	public String showValidationForm(Model model, HttpServletRequest request) {
		ValidationForm validationForm = new ValidationForm();
		validationForm.setValidationLevel(ValidationLevel.ARCHIVAL_DATA); //LTA
		validationForm.setDefaultPolicy(true);
		model.addAttribute("validationForm", validationForm); //Attribute Name/Value 세팅
		setCryptographicSuiteSamples(model);
		return VALIDATION_TILE;
	}


	@PostMapping(value = "/verify-signature", consumes = MediaType.APPLICATION_JSON_VALUE)
	@ResponseBody
	public VerifySignedDocResponse verifySignature(
			@Valid @RequestBody VerifySignedDocRequest verifySignedDocRequest,
			HttpServletRequest request
	) throws JsonProcessingException {

		LOG.info("request : {}", verifySignedDocRequest.toString());

		VerifySignedDocResponse response = new VerifySignedDocResponse();

		// 0. request -> form
		ValidationForm form = ValidationFormMapper.toVerifyDocumentForm(verifySignedDocRequest);

		//--------------------------------------------------
		SignedDocumentValidator documentValidator = SignedDocumentValidator
				.fromDocument(WebAppUtils.toDSSDocument(form.getSignedFile()));
		documentValidator.setCertificateVerifier(getCertificateVerifier(form));

		documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.fromParameters(form.isIncludeCertificateTokens(),
				form.isIncludeTimestampTokens(), form.isIncludeRevocationTokens(), false));

		documentValidator.setIncludeSemantics(form.isIncludeSemantics());

		//defaultPolicy (or If exists InputPolicyFile, then modify code that use it.)
		documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);

		//InputValidationLevel
		documentValidator.setValidationLevel(form.getValidationLevel());

		documentValidator.setValidationTime(getValidationTime(form));

		TokenIdentifierProvider identifierProvider = form.isIncludeUserFriendlyIdentifiers() ?
				new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider();
		documentValidator.setTokenIdentifierProvider(identifierProvider);

		documentValidator.setSigningCertificateSource(userCertificateSource);

		//if exists adjunct cert through input, then set the cert.(optional)
		//setDetachedContents(documentValidator, form);

		//if exists Evidence Records through input, then set the ERs.(optional)
		//setDetachedEvidenceRecords(documentValidator, form);

		Locale locale = request.getLocale();
		LOG.trace("Requested locale : {}", locale);
		if (locale == null) {
			locale = Locale.getDefault();
			LOG.warn("The request locale is null! Use the default one : {}", locale);
		}
		documentValidator.setLocale(locale);

		Reports reports = validate(documentValidator, form);

		SimpleReport euSimple = reports.getSimpleReport();

		String tokenId = euSimple.getFirstSignatureId();
		Indication indication = euSimple.getIndication(tokenId);
		SubIndication subIndication = euSimple.getSubIndication(tokenId);
		boolean isValid = euSimple.isValid(tokenId);

		String msg;
		if (indication.toString().equals("TOTAL_PASSED")) {
			msg = "[SUCCESS] ";
		} else {
			msg = "["+indication+"] "+ subIndication;
		}
//		response.setMessage(indication.toString(), msg);
		response.setSimpleReport(reports);
		response.setDetailedReport(reports);
//		response.setDiagnosticDate(reports);
		response.setValid(isValid);

		//2025.11.18_sujin - purpose : print reports at Front-End
		// response.setReports(reports);
		LOG.info("{}, {}, {} ", indication, subIndication, isValid);
//		LOG.info("response.getSimple : {}", response.getSimpleReport());
//		LOG.info("response.getDetailedReport : {}", response.getDetailedReport());
//		LOG.info("response.getDiagnosticTree : {}", response.getDiagnosticTree());
//		LOG.info("response.getEtsiValidationReport : {}", response.getETSIValidationReport());
		return response;
	}

	private Date getValidationTime(ValidationForm validationForm) {
		if (validationForm.getValidationTime() != null) {
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(validationForm.getValidationTime());
			calendar.add(Calendar.MINUTE, validationForm.getTimezoneDifference());
			return calendar.getTime();
		}
		return null;
	}

	private void setSigningCertificate(DocumentValidator documentValidator, ValidationForm validationForm) {
		CertificateToken signingCertificate = WebAppUtils.toCertificateToken(validationForm.getSigningCertificate());
		if (signingCertificate != null) {
			CertificateSource signingCertificateSource = new CommonCertificateSource();
			signingCertificateSource.addCertificate(signingCertificate);
			documentValidator.setSigningCertificateSource(signingCertificateSource);
		}
	}

	private void setDetachedContents(DocumentValidator documentValidator, ValidationForm validationForm) {
		List<DSSDocument> originalFiles = WebAppUtils.originalFilesToDSSDocuments(validationForm.getOriginalFiles());
		if (Utils.isCollectionNotEmpty(originalFiles)) {
			documentValidator.setDetachedContents(originalFiles);
		}
	}

	private void setDetachedEvidenceRecords(DocumentValidator documentValidator, ValidationForm validationForm) {
		List<DSSDocument> evidenceRecordFiles = WebAppUtils.toDSSDocuments(validationForm.getEvidenceRecordFiles());
		if (Utils.isCollectionNotEmpty(evidenceRecordFiles)) {
			documentValidator.setDetachedEvidenceRecordDocuments(evidenceRecordFiles);
		}
	}

	private CertificateVerifier getCertificateVerifier(ValidationForm certValidationForm) {

		List<CertificateToken> user_certs = userCertificateSource.getCertificates();//.getByEntityKey(new EntityIdentifier(userSourceAlias.getBytes()));
		CertificateToken signingCertificate = user_certs.get(0);
		CertificateToken issuerCertificate = certificateVerifier.getTrustedCertSources().getBySubject(signingCertificate.getIssuer()).iterator().next();
		CertificateToken rootCertificate = certificateVerifier.getTrustedCertSources().getBySubject(issuerCertificate.getIssuer()).iterator().next();

		CommonCertificateVerifier verifier = new CommonCertificateVerifier();

		verifier.setTrustedCertSources(certificateVerifier.getTrustedCertSources());
		verifier.setAdjunctCertSources(certificateVerifier.getAdjunctCertSources());
		verifier.setCrlSource(certificateVerifier.getCrlSource());
		verifier.setOcspSource(certificateVerifier.getOcspSource());
		verifier.setAIASource(certificateVerifier.getAIASource());

		CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
		trusted.addCertificate(rootCertificate);
		verifier.setTrustedCertSources(trusted);

		CommonCertificateSource adjunctSource = new CommonCertificateSource();
		adjunctSource.addCertificate(issuerCertificate);
		adjunctSource.addCertificate(signingCertificate);
		verifier.setAdjunctCertSources(adjunctSource);

		LOG.info("verifier.getCrt : {}",verifier.getTrustedCertSources().toString());
		LOG.info("verifier.getAdjunctCert : {} ",verifier.getAdjunctCertSources().toString());
		return verifier;

		/*
		CertificateSource adjunctCertSource = WebAppUtils.toCertificateSource(certValidationForm.getAdjunctCertificates());

		CertificateVerifier cv;
		if (adjunctCertSource == null) {
			// reuse the default one
			cv = certificateVerifier;
		} else {
			cv = new CertificateVerifierBuilder(certificateVerifier).buildCompleteCopy();
			cv.setAdjunctCertSources(adjunctCertSource);
		}

		return cv;
		 */
	}

	//검증 로직(상세)
	private Reports validate(DocumentValidator documentValidator, ValidationForm validationForm) {
		Reports reports = null;

		//Set currentTime
		Date start = new Date();

		//Initialize ValidationPolicyLoader
		ValidationPolicyLoader validationPolicyLoader;

		//Set Input-PolicyFile(optional)
		MultipartFile policyFile = validationForm.getPolicyFile();
		if (!validationForm.isDefaultPolicy() && policyFile != null && !policyFile.isEmpty()) {
			try (InputStream is = policyFile.getInputStream()) {
				validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(is);
			} catch (IOException e) {
				throw new DSSException("Unable to load validation policy!", e);
			}
		} else if (defaultPolicy != null) {
			try (InputStream is = defaultPolicy.getInputStream()) {
				validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(is);
			} catch (IOException e) {
				throw new InternalServerException(String.format("Unable to parse policy: %s", e.getMessage()), e);
			}
		}
		else {
			throw new IllegalStateException("Validation policy is not correctly initialized!");
		}

		//Set Input-CryptographicSuite (optional)
		MultipartFile cryptographicSuiteFile = validationForm.getCryptographicSuite();
		if (cryptographicSuiteFile != null && !cryptographicSuiteFile.isEmpty()) {
			try (InputStream is = cryptographicSuiteFile.getInputStream()) {
				validationPolicyLoader = validationPolicyLoader.withCryptographicSuite(is);
			} catch (IOException e) {
				throw new DSSException("Unable to load cryptographic suite!", e);
			}
		}

		try {
			//Verify -> Generate Reports
			reports = documentValidator.validateDocument(validationPolicyLoader.create());
		} catch (Exception e) {
			LOG.error(e.getMessage(), e);
		}

		Date end = new Date();
		long duration = end.getTime() - start.getTime();
		LOG.info("Validation process duration : {}ms", duration);

		return reports;
	}

	@RequestMapping(value = "/download-simple-report")
	public void downloadSimpleReport(HttpSession session, HttpServletResponse response) {
		final String simpleReport = (String) session.getAttribute(XML_SIMPLE_REPORT_ATTRIBUTE);
		final String simpleCertificateReport = (String) session.getAttribute(XML_SIMPLE_CERTIFICATE_REPORT_ATTRIBUTE);
		if (Utils.isStringNotEmpty(simpleReport)) {
			try {
				response.setContentType(MimeTypeEnum.PDF.getMimeTypeString());
				response.setHeader("Content-Disposition", "attachment; filename=DSS-Simple-report.pdf");
				fopService.generateSimpleReport(simpleReport, response.getOutputStream());
			} catch (Exception e) {
				LOG.error("An error occurred while generating pdf for simple report : " + e.getMessage(), e);
			}
		} else if (Utils.isStringNotEmpty(simpleCertificateReport)) {
			try {
				response.setContentType(MimeTypeEnum.PDF.getMimeTypeString());
				response.setHeader("Content-Disposition", "attachment; filename=DSS-Simple-certificate-report.pdf");
				fopService.generateSimpleCertificateReport(simpleCertificateReport, response.getOutputStream());
			} catch (Exception e) {
				LOG.error("An error occurred while generating pdf for simple certificate report : " + e.getMessage(), e);
			}
		} else {
			throw new SourceNotFoundException("Simple report not found");
		}
	}

	@RequestMapping(value = "/download-detailed-report")
	public void downloadDetailedReport(HttpSession session, HttpServletResponse response) {
		final String detailedReport = (String) session.getAttribute(XML_DETAILED_REPORT_ATTRIBUTE);
		if (detailedReport == null) {
			throw new SourceNotFoundException("Detailed report not found");
		}
		try {
			response.setContentType(MimeTypeEnum.PDF.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Detailed-report.pdf");
			fopService.generateDetailedReport(detailedReport, response.getOutputStream());
		} catch (Exception e) {
			LOG.error("An error occurred while generating pdf for detailed report : " + e.getMessage(), e);
		}
	}

	@RequestMapping(value = "/download-diagnostic-data")
	public void downloadDiagnosticData(HttpSession session, HttpServletResponse response) {
		String diagnosticData = (String) session.getAttribute(XML_DIAGNOSTIC_DATA_ATTRIBUTE);
		if (diagnosticData == null) {
			throw new SourceNotFoundException("Diagnostic data not found");
		}

		try (InputStream is = new ByteArrayInputStream(diagnosticData.getBytes());
			 OutputStream os = response.getOutputStream()) {
			response.setContentType(MimeTypeEnum.XML.getMimeTypeString());
			response.setHeader("Content-Disposition", "attachment; filename=DSS-Diagnostic-data.xml");
			Utils.copy(is, os);

		} catch (IOException e) {
			LOG.error("An error occurred while downloading diagnostic data : " + e.getMessage(), e);
		}
	}

	@RequestMapping(value = "/diag-data.svg")
	public @ResponseBody ResponseEntity<String> downloadSVG(HttpSession session, HttpServletResponse response) {
		String diagnosticData = (String) session.getAttribute(XML_DIAGNOSTIC_DATA_ATTRIBUTE);
		if (diagnosticData == null) {
			throw new SourceNotFoundException("Diagnostic data not found");
		}

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.valueOf(MimeTypeEnum.SVG.getMimeTypeString()));
		ResponseEntity<String> svgEntity = new ResponseEntity<>(xsltService.generateSVG(diagnosticData), headers,
				HttpStatus.OK);
		return svgEntity;
	}

	@RequestMapping(value = "/download-certificate")
	public void downloadCertificate(@RequestParam(value = "id") String id, HttpSession session, HttpServletResponse response) {
		DiagnosticData diagnosticData = getDiagnosticData(session);
		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(id);
		if (certificate == null) {
			String message = "Certificate " + id + " not found";
			LOG.warn(message);
			throw new SourceNotFoundException(message);
		}
		String pemCert = DSSUtils.convertToPEM(DSSUtils.loadCertificate(certificate.getBinaries()));
		String filename = DSSUtils.getNormalizedString(certificate.getReadableCertificateName()) + ".cer";

		addTokenToResponse(response, filename, pemCert.getBytes());
	}

	@RequestMapping(value = "/download-revocation")
	public void downloadRevocationData(@RequestParam(value = "id") String id, @RequestParam(value = "format") String format, HttpSession session,
									   HttpServletResponse response) {
		DiagnosticData diagnosticData = getDiagnosticData(session);
		RevocationWrapper revocationData = diagnosticData.getRevocationById(id);
		if (revocationData == null) {
			String message = "Revocation data " + id + " not found";
			LOG.warn(message);
			throw new SourceNotFoundException(message);
		}
		String filename = revocationData.getId();
		byte[] binaries;

		if (RevocationType.CRL.equals(revocationData.getRevocationType())) {
			filename += ".crl";

			if (Utils.areStringsEqualIgnoreCase(format, "pem")) {
				String pem = "-----BEGIN CRL-----\n";
				pem += Utils.toBase64(revocationData.getBinaries());
				pem += "\n-----END CRL-----";
				binaries = pem.getBytes();
			} else {
				binaries = revocationData.getBinaries();
			}
		} else {
			filename += ".ocsp";
			binaries = revocationData.getBinaries();
		}

		addTokenToResponse(response, filename, binaries);
	}

	@RequestMapping(value = "/download-timestamp")
	public void downloadTimestamp(@RequestParam(value = "id") String id, @RequestParam(value = "format") String format, HttpSession session,
								  HttpServletResponse response) {
		DiagnosticData diagnosticData = getDiagnosticData(session);
		TimestampWrapper timestamp = diagnosticData.getTimestampById(id);
		if (timestamp == null) {
			String message = "Timestamp " + id + " not found";
			LOG.warn(message);
			throw new SourceNotFoundException(message);
		}
		TimestampType type = timestamp.getType();

		byte[] binaries;
		if (Utils.areStringsEqualIgnoreCase(format, "pem")) {
			String pem = "-----BEGIN TIMESTAMP-----\n";
			pem += Utils.toBase64(timestamp.getBinaries());
			pem += "\n-----END TIMESTAMP-----";
			binaries = pem.getBytes();
		} else {
			binaries = timestamp.getBinaries();
		}

		String filename = type.name() + ".tst";
		addTokenToResponse(response, filename, binaries);
	}

	protected DiagnosticData getDiagnosticData(HttpSession session) {
		String diagnosticDataXml = (String) session.getAttribute(XML_DIAGNOSTIC_DATA_ATTRIBUTE);
		if (diagnosticDataXml == null) {
			throw new SourceNotFoundException("Diagnostic data not found");
		}
		try {
			XmlDiagnosticData xmlDiagData = DiagnosticDataFacade.newFacade().unmarshall(diagnosticDataXml);
			return new DiagnosticData(xmlDiagData);
		} catch (Exception e) {
			LOG.error("An error occurred while generating DiagnosticData from XML : " + e.getMessage(), e);
		}
		return null;
	}

	protected void addTokenToResponse(HttpServletResponse response, String filename, byte[] binaries) {
		response.setContentType(MimeTypeEnum.TST.getMimeTypeString());
		response.setHeader("Content-Disposition", "attachment; filename=" + filename);
		try (InputStream is = new ByteArrayInputStream(binaries); OutputStream os = response.getOutputStream()) {
			Utils.copy(is, os);
		} catch (IOException e) {
			LOG.error("An error occurred while downloading a file : " + e.getMessage(), e);
		}
	}

	@ModelAttribute("validationLevels")
	public ValidationLevel[] getValidationLevels() {
		return new ValidationLevel[] { ValidationLevel.BASIC_SIGNATURES, ValidationLevel.LONG_TERM_DATA, ValidationLevel.ARCHIVAL_DATA };
	}

	@ModelAttribute("displayDownloadPdf")
	public boolean isDisplayDownloadPdf() {
		return true;
	}

	@ModelAttribute("digestAlgos")
	public DigestAlgorithm[] getDigestAlgorithms() {
		// see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
		return new DigestAlgorithm[] { DigestAlgorithm.SHA1, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384,
				DigestAlgorithm.SHA512 };
	}

}