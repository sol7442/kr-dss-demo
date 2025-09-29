package kr.dss.demo.services;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CertificateVerifierBuilder;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;

import eu.europa.esig.dss.ws.signature.common.TimestampTokenConverter;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import kr.dss.demo.exception.SignatureOperationException;
import kr.dss.demo.model.AbstractSignatureForm;
import kr.dss.demo.model.ContainerDocumentForm;
import kr.dss.demo.model.SignatureDocumentForm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

@Service
public class SigningService {

    private static final Logger LOG = LoggerFactory.getLogger(SigningService.class);



    @Autowired
    private CertificateVerifier certificateVerifier;

    @Autowired
    private CommonTrustedCertificateSource userCertificateSource;

    @Value("${dss.users.certs.alias:}")
    private String userSourceAlias;

    @Autowired
    private TSPSource tspSource;

    public InMemoryDocument signDocument(SignatureDocumentForm form) {
        LOG.info("Start signDocument with one document");
        DocumentSignatureService service = getSignatureService(form.getContainerType(), form.getSignatureForm(), form.isSignWithExpiredCertificate());
        AbstractSignatureParameters parameters = fillParameters(form);

        try {
            LOG.info("Document File Name : {}" ,form.getFileName());

            DSSDocument toSignDocument = new InMemoryDocument(form.getDocumentBytes(), form.getFileName());

            SignatureAlgorithm sigAlgorithm = SignatureAlgorithm.getAlgorithm(parameters.getEncryptionAlgorithm(), parameters.getDigestAlgorithm());
            LOG.info("sigAlgorithm : {}" ,sigAlgorithm);
            SignatureValue signatureValue = new SignatureValue(sigAlgorithm, form.getSignatureValue());
            DSSDocument document = service.signDocument(toSignDocument, parameters, signatureValue);


            InMemoryDocument signedDocument = new InMemoryDocument(DSSUtils.toByteArray(document), document.getName(), document.getMimeType());


            LOG.info("End signDocument with one document");
            return signedDocument;
        } catch (Exception e) {
            throw new SignatureOperationException(e.getMessage(), e);
        }
    }

    private AbstractSignatureParameters fillParameters(SignatureDocumentForm form) {
        AbstractSignatureParameters parameters = getSignatureParameters(form.getContainerType(), form.getSignatureForm());
        parameters.setSignaturePackaging(form.getSignaturePackaging());

        fillParameters(parameters, form);

        return parameters;
    }

    private void fillParameters(AbstractSignatureParameters parameters, AbstractSignatureForm form) {
        parameters.setSignatureLevel(form.getSignatureLevel());
        parameters.setDigestAlgorithm(form.getDigestAlgorithm());
        // parameters.setEncryptionAlgorithm(form.getEncryptionAlgorithm()); retrieved from certificate
        parameters.bLevel().setSigningDate(form.getSigningDate());

        if (form.getContentTimestamp() != null) {
            TimestampToken tsToken = TimestampTokenConverter.toTimestampToken(form.getContentTimestamp());
            LOG.debug("TimestampToken : {} ", tsToken);

            parameters.setContentTimestamps(
                    Collections.singletonList(tsToken));
        }


        List<CertificateToken> user_certs = userCertificateSource.getCertificates();//.getByEntityKey(new EntityIdentifier(userSourceAlias.getBytes()));
        CertificateToken signingCertificate = user_certs.get(0);
        LOG.debug("signingCertificate : {} ", signingCertificate);
        parameters.setEncryptionAlgorithm(EncryptionAlgorithm.forKey(signingCertificate.getPublicKey()));
        parameters.setSigningCertificate(signingCertificate);

        List<byte[]> certificateChainBytes = form.getCertificateChain();
        if (Utils.isCollectionNotEmpty(certificateChainBytes)) {
            List<CertificateToken> certificateChain = new LinkedList<>();
            for (byte[] certificate : certificateChainBytes) {
                certificateChain.add(DSSUtils.loadCertificate(certificate));
            }
            parameters.setCertificateChain(certificateChain);
        }

        fillTimestampParameters(parameters, form);
    }
    private void fillTimestampParameters(AbstractSignatureParameters parameters, AbstractSignatureForm form) {
        SignatureForm signatureForm = form.getSignatureForm();

        ASiCContainerType containerType = null;
        if (form instanceof ContainerDocumentForm) {
            containerType = ((ContainerDocumentForm) form).getContainerType();
        }

        TimestampParameters timestampParameters = getTimestampParameters(containerType, signatureForm);
        timestampParameters.setDigestAlgorithm(form.getDigestAlgorithm());

        parameters.setContentTimestampParameters(timestampParameters);
        parameters.setSignatureTimestampParameters(timestampParameters);
        parameters.setArchiveTimestampParameters(timestampParameters);
    }

    private TimestampParameters getTimestampParameters(ASiCContainerType containerType, SignatureForm signatureForm) {
        TimestampParameters parameters = null;
        if (containerType == null) {
            switch (signatureForm) {
                case CAdES:
                    parameters = new CAdESTimestampParameters();
                    break;
                case XAdES:
                    parameters = new XAdESTimestampParameters();
                    break;
                case PAdES:
                    parameters = new PAdESTimestampParameters();
                    break;
                case JAdES:
                    parameters = new JAdESTimestampParameters();
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Not supported signature form for a time-stamp : %s", signatureForm));
            }

        } else {
            switch (signatureForm) {
                case CAdES:
                    ASiCWithCAdESTimestampParameters asicParameters = new ASiCWithCAdESTimestampParameters();
                    asicParameters.aSiC().setContainerType(containerType);
                    parameters = asicParameters;
                    break;
                case XAdES:
                    parameters = new XAdESTimestampParameters();
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Not supported signature form for an ASiC time-stamp : %s", signatureForm));
            }
        }
        return parameters;
    }
    private AbstractSignatureParameters getSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm) {
        AbstractSignatureParameters parameters = null;
        if (containerType != null) {
            parameters = getASiCSignatureParameters(containerType, signatureForm);
        } else {
            switch (signatureForm) {
                case CAdES:
                    parameters = new CAdESSignatureParameters();
                    break;
                case PAdES:
                    PAdESSignatureParameters padesParams = new PAdESSignatureParameters();
                    padesParams.setContentSize(9472 * 2); // double reserved space for signature
                    parameters = padesParams;
                    break;
                case XAdES:
                    parameters = new XAdESSignatureParameters();
                    break;
                case JAdES:
                    JAdESSignatureParameters jadesParameters = new JAdESSignatureParameters();
                    jadesParameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION); // to allow T+ levels + parallel signing
                    jadesParameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH); // to use by default
                    parameters = jadesParameters;
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Unknown signature form : %s", signatureForm));
            }
        }
        return parameters;
    }

    private AbstractSignatureParameters getASiCSignatureParameters(ASiCContainerType containerType, SignatureForm signatureForm) {
        AbstractSignatureParameters parameters = null;
        switch (signatureForm) {
            case CAdES:
                ASiCWithCAdESSignatureParameters asicCadesParams = new ASiCWithCAdESSignatureParameters();
                asicCadesParams.aSiC().setContainerType(containerType);
                parameters = asicCadesParams;
                break;
            case XAdES:
                ASiCWithXAdESSignatureParameters asicXadesParams = new ASiCWithXAdESSignatureParameters();
                asicXadesParams.aSiC().setContainerType(containerType);
                parameters = asicXadesParams;
                break;
            default:
                throw new IllegalArgumentException(String.format("Not supported signature form for an ASiC container : %s", signatureForm));
        }
        return parameters;
    }

    private DocumentSignatureService getSignatureService(ASiCContainerType containerType, SignatureForm signatureForm, boolean signWithExpiredCertificate) {
        CertificateVerifier cv = new CertificateVerifierBuilder(certificateVerifier).buildCompleteCopy();
        if (signWithExpiredCertificate) {
            cv.setAlertOnExpiredCertificate(new LogOnStatusAlert());
        }

        DocumentSignatureService service = null;
        if (containerType != null) {
            service = (DocumentSignatureService) getASiCSignatureService(signatureForm, cv);
        } else {
            switch (signatureForm) {
                case CAdES:
                    service = new CAdESService(cv);
                    break;
                case PAdES:
                    service = new PAdESService(cv);
                    break;
                case XAdES:
                    service = new XAdESService(cv);
                    break;
                case JAdES:
                    service = new JAdESService(cv);
                    break;
                default:
                    throw new IllegalArgumentException(String.format("Unknown signature form : %s", signatureForm));
            }
        }
        service.setTspSource(tspSource);
        return service;
    }

    private MultipleDocumentsSignatureService getASiCSignatureService(SignatureForm signatureForm, CertificateVerifier cv) {
        MultipleDocumentsSignatureService service = null;
        switch (signatureForm) {
            case CAdES:
                service = new ASiCWithCAdESService(cv);
                break;
            case XAdES:
                service = new ASiCWithXAdESService(cv);
                break;
            default:
                throw new IllegalArgumentException(String.format("Not supported signature form for an ASiC container : %s", signatureForm));
        }
        return service;
    }
}
