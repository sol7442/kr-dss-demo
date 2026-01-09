package kr.dss.demo.dto;

import eu.europa.esig.dss.enumerations.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.web.multipart.MultipartFile;

public class SignDocumentRequest {


    @NotNull(message = "{error.to.sign.file.mandatory}")
    private String fileName;

    @NotNull(message = "{error.original.file.empty}")
    private String documentBase64;

    public byte[] getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
    }

    @NotNull(message = "{error.to.sign.digest.mandatory}")
    private byte[] signatureValue;

    public String getFileName(){return this.fileName;}
    public void setFileName(String fileName){this.fileName=fileName;}

    private ASiCContainerType containerType;

    @NotNull(message = "{error.signature.form.mandatory}")
    private SignatureForm signatureForm;

    @NotNull(message = "{error.signature.packaging.mandatory}")
    private SignaturePackaging signaturePackaging;

    @NotNull(message = "{error.signature.level.mandatory}")
    private SignatureLevel signatureLevel;

    @NotNull(message = "{error.digest.algo.mandatory}")
    private DigestAlgorithm digestAlgorithm;


    private boolean signWithExpiredCertificate;

    private boolean addContentTimestamp;

    public SignDocumentRequest() {
    }

    // getters and setters
    public String  getDocumentBase64() { return documentBase64; }
    public void setDocumentBase64(String documentBase64) { this.documentBase64 = documentBase64; }

    public ASiCContainerType getContainerType() { return containerType; }
    public void setContainerType(ASiCContainerType containerType) { this.containerType = containerType; }

    public SignatureForm getSignatureForm() { return signatureForm; }
    public void setSignatureForm(SignatureForm signatureForm) { this.signatureForm = signatureForm; }

    public SignaturePackaging getSignaturePackaging() { return signaturePackaging; }
    public void setSignaturePackaging(SignaturePackaging signaturePackaging) { this.signaturePackaging = signaturePackaging; }

    public SignatureLevel getSignatureLevel() { return signatureLevel; }
    public void setSignatureLevel(SignatureLevel signatureLevel) { this.signatureLevel = signatureLevel; }

    public DigestAlgorithm getDigestAlgorithm() { return digestAlgorithm; }
    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) { this.digestAlgorithm = digestAlgorithm; }

    public boolean isSignWithExpiredCertificate() { return signWithExpiredCertificate; }
    public void setSignWithExpiredCertificate(boolean signWithExpiredCertificate) { this.signWithExpiredCertificate = signWithExpiredCertificate; }

    public boolean isAddContentTimestamp() { return addContentTimestamp; }
    public void setAddContentTimestamp(boolean addContentTimestamp) { this.addContentTimestamp = addContentTimestamp; }

    @Override
    public String toString() {
        return "SignDocumentRequest{" +
                "fileName='" + fileName + '\'' +
                ", documentBase64=" + (documentBase64 != null ? "[BASE64_PRESENT, length=" + documentBase64.length() + "]" : "null") +
                ", signatureValue=" + (signatureValue != null ? "[BYTES_PRESENT, length=" + signatureValue.length + "]" : "null") +
                ", containerType=" + containerType +
                ", signatureForm=" + signatureForm +
                ", signaturePackaging=" + signaturePackaging +
                ", signatureLevel=" + signatureLevel +
                ", digestAlgorithm=" + digestAlgorithm +
                ", signWithExpiredCertificate=" + signWithExpiredCertificate +
                ", addContentTimestamp=" + addContentTimestamp +
                '}';
    }


}
