package kr.dss.demo;

import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.OriginalIdentifierProvider;
import eu.europa.esig.dss.model.identifier.TokenIdentifierProvider;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.identifier.UserFriendlyIdentifierProvider;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;
import kr.dss.demo.exception.InternalServerException;
import kr.dss.demo.model.OriginalFile;
import kr.dss.demo.model.SignatureDocumentForm;
import kr.dss.demo.model.ValidationForm;
import kr.dss.demo.services.SigningService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;
import org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static eu.europa.esig.dss.enumerations.ASiCContainerType.ASiC_E;
import static eu.europa.esig.dss.enumerations.ASiCContainerType.ASiC_S;
import static java.util.Locale.KOREA;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
public class SIG_TEST_BASIC {
    Logger LOG = LoggerFactory.getLogger(SIG_TEST_BASIC.class);

    @Autowired
    private SigningService signingService;

    @Autowired
    private Resource defaultPolicy;

    @Autowired
    protected SignaturePolicyProvider signaturePolicyProvider;

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


    @Test
    public void contextLoads() throws IOException {
        String[] fileList = {"270325.txt", "270325.json", "270325.xml", "dss-documentation.pdf"};
        Path path;
        byte[] content;
        for (String file : fileList) {
            path = Paths.get("src/test/resources/"+file);
            content = Files.readAllBytes(path);

            assertNotNull(content);
            LOG.info("SUCCESS LOAD FILE : {} ", file);
        }
    }

    @Test
    void generateXAdES() throws IOException {
        //1. load file
        String fileName = "270325.xml";
        Path path = Paths.get("src/test/resources/" + fileName);
        byte[] content = Files.readAllBytes(path);

        String jsonArray = "[209,237,254,176,158,78,22,49,106,237,135,168,11,132,248,1,150,68,70,95,22,63,43,10,84,93,3,239,121,244,254,130,222,175,234,173,29,200,59,179,218,118,157,22,153,88,77,134,147,77,186,32,237,38,19,239,220,250,76,28,129,188,147,87]";
        ObjectMapper mapper = new ObjectMapper();
        int[] intArray = mapper.readValue(jsonArray, int[].class);
        // int[] → byte[] 변환
        byte[] signatureValue = new byte[intArray.length];

        for (int i = 0; i < intArray.length; i++) {
            signatureValue[i] = (byte) intArray[i];
        }

        SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
        signatureDocumentForm.setFileName(fileName);
        signatureDocumentForm.setContentType("application/xml");
        signatureDocumentForm.setDocumentBytes(content);

        signatureDocumentForm.setSigningDate(new Date());

        signatureDocumentForm.setSignatureForm(SignatureForm.XAdES);
        signatureDocumentForm.setDigestAlgorithm(DigestAlgorithm.SHA512);
        signatureDocumentForm.setSignatureValue(signatureValue);

        //2025.11.03_sujin : Signing-certificae token was not found !
        //ERROR - after kr-dss-users3.p12... (before kr-dss-user2.p12 ok...)
        // why? 동일이름으로 인증서 다시 만들어보기!!!

        //2. TC1~TC16 : Packaging, Level, Hash Algorithm(fix SHA 512)
        SignaturePackaging[] packaging = {SignaturePackaging.ENVELOPED, SignaturePackaging.ENVELOPING,
                SignaturePackaging.DETACHED}; //, SignaturePackaging.INTERNALLY_DETACHED
        SignatureLevel[] levels = {SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T,
                SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA};

        for (SignaturePackaging var : packaging) {
            signatureDocumentForm.setSignaturePackaging(var);
            //signatureDocumentForm.setSignaturePackaging(SignaturePackaging.INTERNALLY_DETACHED); //에러발생
            for (SignatureLevel lev : levels) {
                signatureDocumentForm.setSignatureLevel(lev);

                //2. signature service - generate signature
                DSSDocument signDocu = signingService.signDocument(signatureDocumentForm);
                assertNotNull(signDocu);
                LOG.info("SUCCESS {}.{}.{}.{}", signatureDocumentForm.getSignatureForm(), signatureDocumentForm.getSignaturePackaging(),
                        signatureDocumentForm.getSignatureLevel(), signatureDocumentForm.getDigestAlgorithm());

                String outputPath = "src/test/resources/output/XAdES/signed-"+signatureDocumentForm.getSignatureForm()+"-"+signatureDocumentForm.getSignaturePackaging()+"-"+
                        signatureDocumentForm.getSignatureLevel()+"-"+signatureDocumentForm.getDigestAlgorithm().getName()+".xml";
                Path outputFile = Paths.get(outputPath);
                Files.createDirectories(outputFile.getParent());

                try (InputStream is = signDocu.openStream()) {
                    Files.copy(is, outputFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    @Test
    void verifyXAdES() throws IOException {
        String fileName = "270325.xml";

        SignaturePackaging[] packaging = {SignaturePackaging.ENVELOPED, SignaturePackaging.ENVELOPING,
                SignaturePackaging.DETACHED}; //, SignaturePackaging.INTERNALLY_DETACHED
        SignatureLevel[] levels = {SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T,
                SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA};

        ValidationForm validationForm = new ValidationForm();
        for (SignaturePackaging var : packaging) {
            //validationForm. packaging
            for (SignatureLevel lev : levels) {
                ValidationLevel validationLevel = LEVEL_MAPPING.get(lev);

                //1. load file(signed-document)
                String outputPath = "src/test/resources/output/XAdES/";
                String testFile = "signed-"+"XAdES"+"-"+var+"-"+lev+"-"+"SHA512"+".xml";

                Path path = Paths.get("src/test/resources/" + fileName);
                byte[] content = Files.readAllBytes(path);
                MultipartFile original = new MockMultipartFile(
                        "documentBase64",
                        "originalFile",
                        null,
                        content
                );
                path = Paths.get(outputPath+testFile);
                byte[] signContent = Files.readAllBytes(path);
                MultipartFile signatures = new MockMultipartFile(
                        "signatureBase64",
                        "signatureFile",
                        null,
                        signContent
                );

                OriginalFile originalFile = new OriginalFile();
                originalFile.setCompleteFile(original);
                validationForm.setOriginalFiles(List.of(originalFile));

                validationForm.setSignedFile(signatures);
                validationForm.setDefaultPolicy(true);
                validationForm.setValidationLevel(validationLevel);

                //-----------------------------------------------
                SignedDocumentValidator documentValidator = SignedDocumentValidator
                        .fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));

                documentValidator.setCertificateVerifier(getCertificateVerifier(validationForm));

                //타임스탬프 토큰 <-- TSA 인증서
                documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.fromParameters(validationForm.isIncludeCertificateTokens(),
                        validationForm.isIncludeTimestampTokens(), validationForm.isIncludeRevocationTokens(), false));

                documentValidator.setIncludeSemantics(validationForm.isIncludeSemantics());

                documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);

                documentValidator.setValidationLevel(validationForm.getValidationLevel());

                documentValidator.setValidationTime(getValidationTime(validationForm));

                TokenIdentifierProvider identifierProvider = validationForm.isIncludeUserFriendlyIdentifiers() ?
                        new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider();
                documentValidator.setTokenIdentifierProvider(identifierProvider);

                setSigningCertificate(documentValidator, validationForm);

                setDetachedContents(documentValidator, validationForm); //maxUploadFile ...

                setDetachedEvidenceRecords(documentValidator, validationForm);

                Locale locale = KOREA;
                LOG.trace("Requested locale : {}", locale);
                if (locale == null) {
                    locale = Locale.getDefault();
                    LOG.warn("The request locale is null! Use the default one : {}", locale);
                }
                documentValidator.setLocale(locale);

                Reports reports = validate(documentValidator, validationForm);

                String tokenId = reports.getSimpleReport().getFirstSignatureId();
                boolean isValid = reports.getSimpleReport().isValid(tokenId);
                Indication indication = reports.getSimpleReport().getIndication(tokenId);

                LOG.info("subIndication : {}", reports.getDetailedReport().getFinalSubIndication(tokenId));

                LOG.info("SUCCESS VERIFY XAdES : {}, {}, {}", isValid, indication.toString(), testFile);
                assertNotNull(reports.getXmlSimpleReport());
                assertFalse(isValid);
            }
        }
    }

    @Test
    void generateCAdES() throws IOException {
        String fileName = "270325.txt";
        Path path = Paths.get("src/test/resources/" + fileName);
        byte[] content = Files.readAllBytes(path);

        String jsonArray = "[209,237,254,176,158,78,22,49,106,237,135,168,11,132,248,1,150,68,70,95,22,63,43,10,84,93,3,239,121,244,254,130,222,175,234,173,29,200,59,179,218,118,157,22,153,88,77,134,147,77,186,32,237,38,19,239,220,250,76,28,129,188,147,87]";
        ObjectMapper mapper = new ObjectMapper();
        int[] intArray = mapper.readValue(jsonArray, int[].class);
        byte[] signatureValue = new byte[intArray.length];

        for (int i = 0; i < intArray.length; i++) {
            signatureValue[i] = (byte) intArray[i];
        }

        SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
        signatureDocumentForm.setFileName(fileName);
        signatureDocumentForm.setContentType("application/pkcs7-signature");
        signatureDocumentForm.setDocumentBytes(content);

        signatureDocumentForm.setSigningDate(new Date());

        signatureDocumentForm.setSignatureForm(SignatureForm.CAdES);
        signatureDocumentForm.setDigestAlgorithm(DigestAlgorithm.SHA512);
        signatureDocumentForm.setSignatureValue(signatureValue);

        //2. TC1~TC16 : Packaging, Level, Hash Algorithm(fix SHA 512)
        SignaturePackaging[] packaging = {SignaturePackaging.ENVELOPING, SignaturePackaging.DETACHED};
        SignatureLevel[] levels = {SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T,
                SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_BASELINE_LTA};

        for (SignaturePackaging var : packaging) {
            signatureDocumentForm.setSignaturePackaging(var);
            for (SignatureLevel lev : levels) {
                signatureDocumentForm.setSignatureLevel(lev);

                //signature service - generate signature
                DSSDocument signDocu = signingService.signDocument(signatureDocumentForm);
                assertNotNull(signDocu);
                LOG.info("SUCCESS {}.{}.{}.{}", signatureDocumentForm.getSignatureForm(), signatureDocumentForm.getSignaturePackaging(),
                        signatureDocumentForm.getSignatureLevel(), signatureDocumentForm.getDigestAlgorithm());

                String outputPath = "src/test/resources/output/CAdES/signed-"+signatureDocumentForm.getSignatureForm()+"-"+signatureDocumentForm.getSignaturePackaging()+"-"+
                        signatureDocumentForm.getSignatureLevel()+"-"+signatureDocumentForm.getDigestAlgorithm().getName()+".p7m";
                Path outputFile = Paths.get(outputPath);
                Files.createDirectories(outputFile.getParent());

                try (InputStream is = signDocu.openStream()) {
                    Files.copy(is, outputFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }

    }

    @Test
    void verifyCAdES() throws IOException {
        String fileName = "270325.txt";

        SignaturePackaging[] packaging = {SignaturePackaging.ENVELOPING, SignaturePackaging.DETACHED};
        SignatureLevel[] levels = {SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T,
                SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_BASELINE_LTA};

        ValidationForm validationForm = new ValidationForm();
        for (SignaturePackaging var : packaging) {
            //validationForm. packaging
            for (SignatureLevel lev : levels) {
                ValidationLevel validationLevel = LEVEL_MAPPING.get(lev);

                //1. load file(signed-document)
                String outputPath = "src/test/resources/output/CAdES/";
                String testFile = "signed-"+"CAdES"+"-"+var+"-"+lev+"-"+"SHA512"+".p7m";

                Path path = Paths.get("src/test/resources/" + fileName);
                byte[] content = Files.readAllBytes(path);
                MultipartFile original = new MockMultipartFile(
                        "documentBase64",
                        "originalFile",
                        null,
                        content
                );
                path = Paths.get(outputPath+testFile);
                byte[] signContent = Files.readAllBytes(path);
                MultipartFile signatures = new MockMultipartFile(
                        "signatureBase64",
                        "signatureFile",
                        null,
                        signContent
                );

                OriginalFile originalFile = new OriginalFile();
                originalFile.setCompleteFile(original);
                validationForm.setOriginalFiles(List.of(originalFile));

                validationForm.setSignedFile(signatures);
                validationForm.setDefaultPolicy(true);
                validationForm.setValidationLevel(validationLevel);

                //-----------------------------------------------
                SignedDocumentValidator documentValidator = SignedDocumentValidator
                        .fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));

                documentValidator.setCertificateVerifier(getCertificateVerifier(validationForm));

                //타임스탬프 토큰 <-- TSA 인증서
                documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.fromParameters(validationForm.isIncludeCertificateTokens(),
                        validationForm.isIncludeTimestampTokens(), validationForm.isIncludeRevocationTokens(), false));

                documentValidator.setIncludeSemantics(validationForm.isIncludeSemantics());

                documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);

                documentValidator.setValidationLevel(validationForm.getValidationLevel());

                documentValidator.setValidationTime(getValidationTime(validationForm));

                TokenIdentifierProvider identifierProvider = validationForm.isIncludeUserFriendlyIdentifiers() ?
                        new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider();
                documentValidator.setTokenIdentifierProvider(identifierProvider);

                setSigningCertificate(documentValidator, validationForm);

                setDetachedContents(documentValidator, validationForm); //maxUploadFile ...

                setDetachedEvidenceRecords(documentValidator, validationForm);

                Locale locale = KOREA;
                LOG.trace("Requested locale : {}", locale);
                if (locale == null) {
                    locale = Locale.getDefault();
                    LOG.warn("The request locale is null! Use the default one : {}", locale);
                }
                documentValidator.setLocale(locale);

                Reports reports = validate(documentValidator, validationForm);

                String tokenId = reports.getSimpleReport().getFirstSignatureId();
                boolean isValid = reports.getSimpleReport().isValid(tokenId);
                Indication indication = reports.getSimpleReport().getIndication(tokenId);

                LOG.info("subIndication : {}", reports.getDetailedReport().getFinalSubIndication(tokenId));

                LOG.info("SUCCESS VERIFY CAdES : {}, {}, {}", isValid, indication.toString(), testFile);
                assertNotNull(reports.getXmlSimpleReport());
                assertFalse(isValid);
            }
        }
    }
    @Test
    void generatePAdES() throws IOException {
        String fileName = "dss-documentation.pdf";
        Path path = Paths.get("src/test/resources/" + fileName);
        byte[] content = Files.readAllBytes(path);

        String jsonArray = "[209,237,254,176,158,78,22,49,106,237,135,168,11,132,248,1,150,68,70,95,22,63,43,10,84,93,3,239,121,244,254,130,222,175,234,173,29,200,59,179,218,118,157,22,153,88,77,134,147,77,186,32,237,38,19,239,220,250,76,28,129,188,147,87]";
        ObjectMapper mapper = new ObjectMapper();
        int[] intArray = mapper.readValue(jsonArray, int[].class);
        byte[] signatureValue = new byte[intArray.length];

        for (int i = 0; i < intArray.length; i++) {
            signatureValue[i] = (byte) intArray[i];
        }

        SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
        signatureDocumentForm.setFileName(fileName);
        signatureDocumentForm.setContentType("application/pdf");
        signatureDocumentForm.setDocumentBytes(content);

        signatureDocumentForm.setSigningDate(new Date());

        signatureDocumentForm.setSignatureForm(SignatureForm.PAdES);
        signatureDocumentForm.setDigestAlgorithm(DigestAlgorithm.SHA512);
        signatureDocumentForm.setSignatureValue(signatureValue);

        //2. TC1~TC16 : Packaging, Level, Hash Algorithm(fix SHA 512)
        SignaturePackaging[] packaging = {SignaturePackaging.ENVELOPED};
        SignatureLevel[] levels = {SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T,
                SignatureLevel.PAdES_BASELINE_LT, SignatureLevel.PAdES_BASELINE_LTA};

        for (SignaturePackaging var : packaging) {
            signatureDocumentForm.setSignaturePackaging(var);
            for (SignatureLevel lev : levels) {
                signatureDocumentForm.setSignatureLevel(lev);

                //2. signature service - generate signature
                DSSDocument signDocu = signingService.signDocument(signatureDocumentForm);
                assertNotNull(signDocu);
                LOG.info("SUCCESS {}.{}.{}.{}", signatureDocumentForm.getSignatureForm(), signatureDocumentForm.getSignaturePackaging(),
                        signatureDocumentForm.getSignatureLevel(), signatureDocumentForm.getDigestAlgorithm());

                String outputPath = "src/test/resources/output/PAdES/signed-"+signatureDocumentForm.getSignatureForm()+"-"+signatureDocumentForm.getSignaturePackaging()+"-"+
                        signatureDocumentForm.getSignatureLevel()+"-"+signatureDocumentForm.getDigestAlgorithm().getName()+".pdf";
                Path outputFile = Paths.get(outputPath);
                Files.createDirectories(outputFile.getParent());

                try (InputStream is = signDocu.openStream()) {
                    Files.copy(is, outputFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    @Test
    void verifyPAdES() throws IOException {
        String fileName = "dss-documentation.pdf";

        SignaturePackaging[] packaging = {SignaturePackaging.ENVELOPED};
        SignatureLevel[] levels = {SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PAdES_BASELINE_T,
                SignatureLevel.PAdES_BASELINE_LT, SignatureLevel.PAdES_BASELINE_LTA};

        ValidationForm validationForm = new ValidationForm();
        for (SignaturePackaging var : packaging) {
            //validationForm. packaging
            for (SignatureLevel lev : levels) {
                ValidationLevel validationLevel = LEVEL_MAPPING.get(lev);

                //1. load file(signed-document)
                String outputPath = "src/test/resources/output/PAdES/";
                String testFile = "signed-" + "PAdES" + "-" + var + "-" + lev + "-" + "SHA512" + ".pdf";

                Path path = Paths.get("src/test/resources/" + fileName);
                byte[] content = Files.readAllBytes(path);
                MultipartFile original = new MockMultipartFile(
                        "documentBase64",
                        "originalFile",
                        null,
                        content
                );
                path = Paths.get(outputPath + testFile);
                byte[] signContent = Files.readAllBytes(path);
                MultipartFile signatures = new MockMultipartFile(
                        "signatureBase64",
                        "signatureFile",
                        null,
                        signContent
                );

                OriginalFile originalFile = new OriginalFile();
                originalFile.setCompleteFile(original);
                validationForm.setOriginalFiles(List.of(originalFile));

                validationForm.setSignedFile(signatures);
                validationForm.setDefaultPolicy(true);
                validationForm.setValidationLevel(validationLevel);

                //-----------------------------------------------
                SignedDocumentValidator documentValidator = SignedDocumentValidator
                        .fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));

                documentValidator.setCertificateVerifier(getCertificateVerifier(validationForm));

                //타임스탬프 토큰 <-- TSA 인증서
                documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.fromParameters(validationForm.isIncludeCertificateTokens(),
                        validationForm.isIncludeTimestampTokens(), validationForm.isIncludeRevocationTokens(), false));

                documentValidator.setIncludeSemantics(validationForm.isIncludeSemantics());

                documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);

                documentValidator.setValidationLevel(validationForm.getValidationLevel());

                documentValidator.setValidationTime(getValidationTime(validationForm));

                TokenIdentifierProvider identifierProvider = validationForm.isIncludeUserFriendlyIdentifiers() ?
                        new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider();
                documentValidator.setTokenIdentifierProvider(identifierProvider);

                setSigningCertificate(documentValidator, validationForm);

                setDetachedContents(documentValidator, validationForm); //maxUploadFile ...

                setDetachedEvidenceRecords(documentValidator, validationForm);

                Locale locale = KOREA;
                LOG.trace("Requested locale : {}", locale);
                if (locale == null) {
                    locale = Locale.getDefault();
                    LOG.warn("The request locale is null! Use the default one : {}", locale);
                }
                documentValidator.setLocale(locale);

                Reports reports = validate(documentValidator, validationForm);

                String tokenId = reports.getSimpleReport().getFirstSignatureId();
                boolean isValid = reports.getSimpleReport().isValid(tokenId);
                Indication indication = reports.getSimpleReport().getIndication(tokenId);

                LOG.info("subIndication : {}", reports.getDetailedReport().getFinalSubIndication(tokenId));

                LOG.info("SUCCESS VERIFY PAdES : {}, {}, {}", isValid, indication.toString(), testFile);
                assertNotNull(reports.getXmlSimpleReport());
                assertFalse(isValid);

            }
        }
    }

    @Test
    void generateJAdES() throws IOException {
        String fileName = "270325.json";
        Path path = Paths.get("src/test/resources/" + fileName);
        byte[] content = Files.readAllBytes(path);

        String jsonArray = "[209,237,254,176,158,78,22,49,106,237,135,168,11,132,248,1,150,68,70,95,22,63,43,10,84,93,3,239,121,244,254,130,222,175,234,173,29,200,59,179,218,118,157,22,153,88,77,134,147,77,186,32,237,38,19,239,220,250,76,28,129,188,147,87]";
        ObjectMapper mapper = new ObjectMapper();
        int[] intArray = mapper.readValue(jsonArray, int[].class);
        byte[] signatureValue = new byte[intArray.length];

        for (int i = 0; i < intArray.length; i++) {
            signatureValue[i] = (byte) intArray[i];
        }

        SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
        signatureDocumentForm.setFileName(fileName);
        signatureDocumentForm.setContentType("application/json");
        signatureDocumentForm.setDocumentBytes(content);

        signatureDocumentForm.setSigningDate(new Date());

        signatureDocumentForm.setSignatureForm(SignatureForm.JAdES);
        signatureDocumentForm.setDigestAlgorithm(DigestAlgorithm.SHA512);
        signatureDocumentForm.setSignatureValue(signatureValue);

        //2. TC1~TC16 : Packaging, Level, Hash Algorithm(fix SHA 512)
        SignaturePackaging[] packaging = {SignaturePackaging.ENVELOPING, SignaturePackaging.DETACHED};
        SignatureLevel[] levels = {SignatureLevel.JAdES_BASELINE_B, SignatureLevel.JAdES_BASELINE_T,
                SignatureLevel.JAdES_BASELINE_LT, SignatureLevel.JAdES_BASELINE_LTA};

        for (SignaturePackaging var : packaging) {
            signatureDocumentForm.setSignaturePackaging(var);
            for (SignatureLevel lev : levels) {
                signatureDocumentForm.setSignatureLevel(lev);

                //2. signature service - generate signature
                DSSDocument signDocu = signingService.signDocument(signatureDocumentForm);
                assertNotNull(signDocu);
                LOG.info("SUCCESS {}.{}.{}.{}", signatureDocumentForm.getSignatureForm(), signatureDocumentForm.getSignaturePackaging(),
                        signatureDocumentForm.getSignatureLevel(), signatureDocumentForm.getDigestAlgorithm());

                String outputPath = "src/test/resources/output/JAdES/signed-"+signatureDocumentForm.getSignatureForm()+"-"+signatureDocumentForm.getSignaturePackaging()+"-"+
                        signatureDocumentForm.getSignatureLevel()+"-"+signatureDocumentForm.getDigestAlgorithm().getName()+".json";
                Path outputFile = Paths.get(outputPath);
                Files.createDirectories(outputFile.getParent());

                try (InputStream is = signDocu.openStream()) {
                    Files.copy(is, outputFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }
    }

    @Test
    void verifyJAdES() throws IOException {
        String fileName = "270325.json";

        SignaturePackaging[] packaging = {SignaturePackaging.ENVELOPING, SignaturePackaging.DETACHED};
        SignatureLevel[] levels = {SignatureLevel.JAdES_BASELINE_B, SignatureLevel.JAdES_BASELINE_T,
                SignatureLevel.JAdES_BASELINE_LT, SignatureLevel.JAdES_BASELINE_LTA};

        ValidationForm validationForm = new ValidationForm();
        for (SignaturePackaging var : packaging) {
            //validationForm. packaging
            for (SignatureLevel lev : levels) {
                ValidationLevel validationLevel = LEVEL_MAPPING.get(lev);

                //1. load file(signed-document)
                String outputPath = "src/test/resources/output/JAdES/";
                String testFile = "signed-"+"JAdES"+"-"+var+"-"+lev+"-"+"SHA512"+".json";

                Path path = Paths.get("src/test/resources/" + fileName);
                byte[] content = Files.readAllBytes(path);
                MultipartFile original = new MockMultipartFile(
                        "documentBase64",
                        "originalFile",
                        null,
                        content
                );
                path = Paths.get(outputPath+testFile);
                byte[] signContent = Files.readAllBytes(path);
                MultipartFile signatures = new MockMultipartFile(
                        "signatureBase64",
                        "signatureFile",
                        null,
                        signContent
                );

                OriginalFile originalFile = new OriginalFile();
                originalFile.setCompleteFile(original);
                validationForm.setOriginalFiles(List.of(originalFile));

                validationForm.setSignedFile(signatures);
                validationForm.setDefaultPolicy(true);
                validationForm.setValidationLevel(validationLevel);

                //-----------------------------------------------
                SignedDocumentValidator documentValidator = SignedDocumentValidator
                        .fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));

                documentValidator.setCertificateVerifier(getCertificateVerifier(validationForm));

                //타임스탬프 토큰 <-- TSA 인증서
                documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.fromParameters(validationForm.isIncludeCertificateTokens(),
                        validationForm.isIncludeTimestampTokens(), validationForm.isIncludeRevocationTokens(), false));

                documentValidator.setIncludeSemantics(validationForm.isIncludeSemantics());

                documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);

                documentValidator.setValidationLevel(validationForm.getValidationLevel());

                documentValidator.setValidationTime(getValidationTime(validationForm));

                TokenIdentifierProvider identifierProvider = validationForm.isIncludeUserFriendlyIdentifiers() ?
                        new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider();
                documentValidator.setTokenIdentifierProvider(identifierProvider);

                setSigningCertificate(documentValidator, validationForm);

                setDetachedContents(documentValidator, validationForm); //maxUploadFile ...

                setDetachedEvidenceRecords(documentValidator, validationForm);

                Locale locale = KOREA;
                LOG.trace("Requested locale : {}", locale);
                if (locale == null) {
                    locale = Locale.getDefault();
                    LOG.warn("The request locale is null! Use the default one : {}", locale);
                }
                documentValidator.setLocale(locale);

                Reports reports = validate(documentValidator, validationForm);

                String tokenId = reports.getSimpleReport().getFirstSignatureId();
                boolean isValid = reports.getSimpleReport().isValid(tokenId);
                Indication indication = reports.getSimpleReport().getIndication(tokenId);

                LOG.info("subIndication : {}", reports.getDetailedReport().getFinalSubIndication(tokenId));

                LOG.info("SUCCESS VERIFY JAdES : {}, {}, {}", isValid, indication.toString(), testFile);
                assertNotNull(reports.getXmlSimpleReport());
                assertFalse(isValid);
            }
        }

    }

    @Test
    void generateASiCS() throws IOException {
        //PKCS7 -> application/pkcs7-mime
        //default -> contentType = "application/octet-stream";
        String[] fileList = {"270325.xml", "270325.txt"};
        String[] sigForm = {"XAdES", "CAdES"};
        String[] contents = {"application/xml", "application/pkcs7-signature"};
        SignatureLevel[][] levels = {{SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T,
                SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA},
                {SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T,
                        SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_BASELINE_LTA}};

        for (int i=0; i<fileList.length; i++) {
            String fileName = fileList[i];
            Path path = Paths.get("src/test/resources/" + fileName);

            byte[] content = Files.readAllBytes(path);

            String jsonArray = "[209,237,254,176,158,78,22,49,106,237,135,168,11,132,248,1,150,68,70,95,22,63,43,10,84,93,3,239,121,244,254,130,222,175,234,173,29,200,59,179,218,118,157,22,153,88,77,134,147,77,186,32,237,38,19,239,220,250,76,28,129,188,147,87]";
            ObjectMapper mapper = new ObjectMapper();
            int[] intArray = mapper.readValue(jsonArray, int[].class);
            // int[] → byte[] 변환
            byte[] signatureValue = new byte[intArray.length];

            for (int j = 0; j < intArray.length; j++) {
                signatureValue[j] = (byte) intArray[j];
            }

            SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
            signatureDocumentForm.setFileName(fileName);
            signatureDocumentForm.setContentType(contents[i]);
            signatureDocumentForm.setDocumentBytes(content);

            signatureDocumentForm.setSigningDate(new Date());

            signatureDocumentForm.setContainerType(ASiC_S);
            signatureDocumentForm.setSignatureForm(SignatureForm.valueOf(sigForm[i]));
            signatureDocumentForm.setDigestAlgorithm(DigestAlgorithm.SHA512);
            signatureDocumentForm.setSignatureValue(signatureValue);

            //2. TC1~TC16 : Packaging, Level, Hash Algorithm(fix SHA 512)
            SignaturePackaging[] packaging = {SignaturePackaging.DETACHED};

            for (SignaturePackaging var : packaging) {
                signatureDocumentForm.setSignaturePackaging(var);
                for (SignatureLevel lev : levels[i]) {
                    signatureDocumentForm.setSignatureLevel(lev);

                    //2. signature service - generate signature
                    DSSDocument signDocu = signingService.signDocument(signatureDocumentForm);
                    assertNotNull(signDocu);
                    LOG.info("SUCCESS {}.{}.{}.{}", signatureDocumentForm.getSignatureForm(), signatureDocumentForm.getSignaturePackaging(),
                            signatureDocumentForm.getSignatureLevel(), signatureDocumentForm.getDigestAlgorithm());

                    String outputPath = "src/test/resources/output/ASiC-S/signed-"+"ASiC-S"+"-"+signatureDocumentForm.getSignaturePackaging()+"-"+
                            signatureDocumentForm.getSignatureLevel()+"-"+signatureDocumentForm.getDigestAlgorithm().getName()+".scs";
                    Path outputFile = Paths.get(outputPath);
                    Files.createDirectories(outputFile.getParent());

                    try (InputStream is = signDocu.openStream()) {
                        Files.copy(is, outputFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
        }
    }

    //작성 중
    @Test
    void verifyASiCS() throws IOException {
        String[] fileList = {"270325.xml", "270325.txt"};
        String[] sigForm = {"XAdES", "CAdES"};
        String[] contents = {"application/xml", "application/pkcs7-signature"};

        SignaturePackaging[] packaging = {SignaturePackaging.DETACHED};
        SignatureLevel[][] levels = {{SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T,
                SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA},
                {SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T,
                        SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_BASELINE_LTA}};

        for (int i=0; i<fileList.length; i++) {
            String fileName = fileList[i];
            String sigFormat = sigForm[i];
            LOG.info("sigFormat: {} ", sigFormat);

            ValidationForm validationForm = new ValidationForm();
            for (SignaturePackaging var : packaging) { //only one : DETACHED
                for (SignatureLevel lev : levels[i]) {
                    ValidationLevel validationLevel = LEVEL_MAPPING.get(lev);

                    //1. load file(signed-document)
                    String outputPath = "src/test/resources/output/ASiC-S/";
                    String testFile = "signed-"+"ASiC-S"+"-"+var+"-"+lev+"-"+"SHA512"+".scs";
                    LOG.info("testFile: {} ", testFile);

                    Path path = Paths.get("src/test/resources/" + fileName);
                    byte[] content = Files.readAllBytes(path);
                    MultipartFile original = new MockMultipartFile(
                            "documentBase64",
                            "originalFile",
                            null,
                            content
                    );
                    path = Paths.get(outputPath+testFile);
                    byte[] signContent = Files.readAllBytes(path);
                    MultipartFile signatures = new MockMultipartFile(
                            "signatureBase64",
                            "signatureFile",
                            null,
                            signContent
                    );

                    OriginalFile originalFile = new OriginalFile();
                    originalFile.setCompleteFile(original);
                    validationForm.setOriginalFiles(List.of(originalFile));

                    validationForm.setSignedFile(signatures);
                    validationForm.setDefaultPolicy(true);
                    validationForm.setValidationLevel(validationLevel);

                    //-----------------------------------------------
                    SignedDocumentValidator documentValidator = SignedDocumentValidator
                            .fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));

                    documentValidator.setCertificateVerifier(getCertificateVerifier(validationForm));

                    //타임스탬프 토큰 <-- TSA 인증서
                    documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.fromParameters(validationForm.isIncludeCertificateTokens(),
                            validationForm.isIncludeTimestampTokens(), validationForm.isIncludeRevocationTokens(), false));

                    documentValidator.setIncludeSemantics(validationForm.isIncludeSemantics());

                    documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);

                    documentValidator.setValidationLevel(validationForm.getValidationLevel());

                    documentValidator.setValidationTime(getValidationTime(validationForm));

                    TokenIdentifierProvider identifierProvider = validationForm.isIncludeUserFriendlyIdentifiers() ?
                            new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider();
                    documentValidator.setTokenIdentifierProvider(identifierProvider);

                    setSigningCertificate(documentValidator, validationForm);

                    setDetachedContents(documentValidator, validationForm); //maxUploadFile ...

                    setDetachedEvidenceRecords(documentValidator, validationForm);

                    Locale locale = KOREA;
                    LOG.trace("Requested locale : {}", locale);
                    if (locale == null) {
                        locale = Locale.getDefault();
                        LOG.warn("The request locale is null! Use the default one : {}", locale);
                    }
                    documentValidator.setLocale(locale);

                    Reports reports = validate(documentValidator, validationForm);

                    String tokenId = reports.getSimpleReport().getFirstSignatureId();
                    boolean isValid = reports.getSimpleReport().isValid(tokenId);
                    Indication indication = reports.getSimpleReport().getIndication(tokenId);

                    LOG.info("subIndication : {}", reports.getDetailedReport().getFinalSubIndication(tokenId));

                    LOG.info("SUCCESS VERIFY XAdES : {}, {}, {}", isValid, indication.toString(), testFile);
                    assertNotNull(reports.getXmlSimpleReport());
                    assertFalse(isValid);
                }
            }
        }
    }

    @Test
    void generateASiCE() throws IOException {
        String[] fileList = {"270325.xml", "270325.txt"};
        String[] sigForm = {"XAdES", "CAdES"};
        String[] contents = {"application/xml", "application/pkcs7-signature"};
        SignatureLevel[][] levels = {{SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T,
                SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA},
                {SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T,
                        SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_BASELINE_LTA}};

        for (int i=0; i<fileList.length; i++) {
            String fileName = fileList[i];
            Path path = Paths.get("src/test/resources/" + fileName);

            byte[] content = Files.readAllBytes(path);

            String jsonArray = "[209,237,254,176,158,78,22,49,106,237,135,168,11,132,248,1,150,68,70,95,22,63,43,10,84,93,3,239,121,244,254,130,222,175,234,173,29,200,59,179,218,118,157,22,153,88,77,134,147,77,186,32,237,38,19,239,220,250,76,28,129,188,147,87]";
            ObjectMapper mapper = new ObjectMapper();
            int[] intArray = mapper.readValue(jsonArray, int[].class);
            // int[] → byte[] 변환
            byte[] signatureValue = new byte[intArray.length];

            for (int j = 0; j < intArray.length; j++) {
                signatureValue[j] = (byte) intArray[j];
            }

            SignatureDocumentForm signatureDocumentForm = new SignatureDocumentForm();
            signatureDocumentForm.setFileName(fileName);
            signatureDocumentForm.setContentType(contents[i]);
            signatureDocumentForm.setDocumentBytes(content);

            signatureDocumentForm.setSigningDate(new Date());

            signatureDocumentForm.setContainerType(ASiC_E);
            signatureDocumentForm.setSignatureForm(SignatureForm.valueOf(sigForm[i]));
            signatureDocumentForm.setDigestAlgorithm(DigestAlgorithm.SHA512);
            signatureDocumentForm.setSignatureValue(signatureValue);

            //2. TC1~TC16 : Packaging, Level, Hash Algorithm(fix SHA 512)
            SignaturePackaging[] packaging = {SignaturePackaging.DETACHED};

            for (SignaturePackaging var : packaging) {
                signatureDocumentForm.setSignaturePackaging(var);
                for (SignatureLevel lev : levels[i]) {
                    signatureDocumentForm.setSignatureLevel(lev);

                    //2. signature service - generate signature
                    DSSDocument signDocu = signingService.signDocument(signatureDocumentForm);
                    assertNotNull(signDocu);
                    LOG.info("SUCCESS {}.{}.{}.{}", signatureDocumentForm.getSignatureForm(), signatureDocumentForm.getSignaturePackaging(),
                            signatureDocumentForm.getSignatureLevel(), signatureDocumentForm.getDigestAlgorithm());

                    String outputPath = "src/test/resources/output/ASiC-E/signed-"+"ASiC-E"+"-"+signatureDocumentForm.getSignaturePackaging()+"-"+
                            signatureDocumentForm.getSignatureLevel()+"-"+signatureDocumentForm.getDigestAlgorithm().getName()+".sce";
                    Path outputFile = Paths.get(outputPath);
                    Files.createDirectories(outputFile.getParent());

                    try (InputStream is = signDocu.openStream()) {
                        Files.copy(is, outputFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
        }

    }

    @Test
    void verifyASiCE() throws IOException {
        String[] fileList = {"270325.xml", "270325.txt"};
        String[] sigForm = {"XAdES", "CAdES"};
        String[] contents = {"application/xml", "application/pkcs7-signature"};

        SignaturePackaging[] packaging = {SignaturePackaging.DETACHED};
        SignatureLevel[][] levels = {{SignatureLevel.XAdES_BASELINE_B, SignatureLevel.XAdES_BASELINE_T,
                SignatureLevel.XAdES_BASELINE_LT, SignatureLevel.XAdES_BASELINE_LTA},
                {SignatureLevel.CAdES_BASELINE_B, SignatureLevel.CAdES_BASELINE_T,
                        SignatureLevel.CAdES_BASELINE_LT, SignatureLevel.CAdES_BASELINE_LTA}};

        for (int i=0; i<fileList.length; i++) {
            String fileName = fileList[i];
            String sigFormat = sigForm[i];
            LOG.info("sigFormat: {} ", sigFormat);

            ValidationForm validationForm = new ValidationForm();
            for (SignaturePackaging var : packaging) { //only one : DETACHED
                for (SignatureLevel lev : levels[i]) {
                    ValidationLevel validationLevel = LEVEL_MAPPING.get(lev);

                    //1. load file(signed-document)
                    String outputPath = "src/test/resources/output/ASiC-E/";
                    String testFile = "signed-"+"ASiC-E"+"-"+var+"-"+lev+"-"+"SHA512"+".sce";
                    LOG.info("testFile: {} ", testFile);

                    Path path = Paths.get("src/test/resources/" + fileName);
                    byte[] content = Files.readAllBytes(path);
                    MultipartFile original = new MockMultipartFile(
                            "documentBase64",
                            "originalFile",
                            null,
                            content
                    );
                    path = Paths.get(outputPath+testFile);
                    byte[] signContent = Files.readAllBytes(path);
                    MultipartFile signatures = new MockMultipartFile(
                            "signatureBase64",
                            "signatureFile",
                            null,
                            signContent
                    );

                    OriginalFile originalFile = new OriginalFile();
                    originalFile.setCompleteFile(original);
                    validationForm.setOriginalFiles(List.of(originalFile));

                    validationForm.setSignedFile(signatures);
                    validationForm.setDefaultPolicy(true);
                    validationForm.setValidationLevel(validationLevel);

                    //-----------------------------------------------
                    SignedDocumentValidator documentValidator = SignedDocumentValidator
                            .fromDocument(WebAppUtils.toDSSDocument(validationForm.getSignedFile()));

                    documentValidator.setCertificateVerifier(getCertificateVerifier(validationForm));

                    //타임스탬프 토큰 <-- TSA 인증서
                    documentValidator.setTokenExtractionStrategy(TokenExtractionStrategy.fromParameters(validationForm.isIncludeCertificateTokens(),
                            validationForm.isIncludeTimestampTokens(), validationForm.isIncludeRevocationTokens(), false));

                    documentValidator.setIncludeSemantics(validationForm.isIncludeSemantics());

                    documentValidator.setSignaturePolicyProvider(signaturePolicyProvider);

                    documentValidator.setValidationLevel(validationForm.getValidationLevel());

                    documentValidator.setValidationTime(getValidationTime(validationForm));

                    TokenIdentifierProvider identifierProvider = validationForm.isIncludeUserFriendlyIdentifiers() ?
                            new UserFriendlyIdentifierProvider() : new OriginalIdentifierProvider();
                    documentValidator.setTokenIdentifierProvider(identifierProvider);

                    setSigningCertificate(documentValidator, validationForm);

                    setDetachedContents(documentValidator, validationForm); //maxUploadFile ...

                    setDetachedEvidenceRecords(documentValidator, validationForm);

                    Locale locale = KOREA;
                    LOG.trace("Requested locale : {}", locale);
                    if (locale == null) {
                        locale = Locale.getDefault();
                        LOG.warn("The request locale is null! Use the default one : {}", locale);
                    }
                    documentValidator.setLocale(locale);

                    Reports reports = validate(documentValidator, validationForm);

                    String tokenId = reports.getSimpleReport().getFirstSignatureId();
                    boolean isValid = reports.getSimpleReport().isValid(tokenId);
                    Indication indication = reports.getSimpleReport().getIndication(tokenId);

                    LOG.info("subIndication : {}", reports.getDetailedReport().getFinalSubIndication(tokenId));

                    LOG.info("SUCCESS VERIFY XAdES : {}, {}, {}", isValid, indication.toString(), testFile);
                    assertNotNull(reports.getXmlSimpleReport());
                    assertFalse(isValid);
                }
            }
        }

    }

    @Autowired
    protected CertificateVerifier certificateVerifier;

    private CertificateVerifier getCertificateVerifier(ValidationForm certValidationForm) {
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
}
