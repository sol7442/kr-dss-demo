package kr.dss.demo.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import jakarta.validation.constraints.NotNull;

import java.util.Date;

// Set Verify Request DTO for KR-DSS.
public class VerifySignedDocRequest {
    @JsonProperty("documentBase64")
    private String documentBase64;

    @JsonProperty("signatureBase64")
    @NotNull (message = "{error.to.verify.signedFile.empty}")
    private String signatureBase64;

    @JsonProperty("container")
    private String container;

    @JsonProperty("signatureFormat")
    private SignatureForm signatureFormat;

    @JsonProperty("signatureLevel")
    private SignatureLevel signatureLevel;

    @JsonProperty("validationTime")
    private String validationTime;

    @JsonProperty("trustAnchor")
    private String trustAnchor;

    //---------------------------------------
    public VerifySignedDocRequest() {}

    public VerifySignedDocRequest(String signature) {
        this.signatureBase64 = signature;
    }
    public String getSignature() { return this.signatureBase64; }
    //    public void setPolicy(PolicyProperties policy) { this.policy = policy; }
    public void setDocument(String document) {
        this.documentBase64 = document;
    }
    //    public PolicyProperties getPolicy() { return this.policy; }
    public String getDocument() { return this.documentBase64; }

    public String getContainer() { return container; }
    public void setContainer(String container) { this.container = container; }
    public SignatureForm getSignatureFormat() { return signatureFormat; }
    public void setSignatureFormat(SignatureForm signatureFormat) { this.signatureFormat = signatureFormat; }
    public SignatureLevel getSignatureLevel() { return signatureLevel; }
    public void setSignatureLevel(SignatureLevel signatureLevel) { this.signatureLevel = signatureLevel; }
    public String getValidationTime() { return validationTime; }
    public void setValidationTime(String validationTime) { this.validationTime = validationTime; }
    public String getTrustAnchor() { return trustAnchor; }
    public void setTrustAnchor(String trustAnchor) { this.trustAnchor = trustAnchor; }

    @Override
    public String toString() {
        return "VerifySignedDocRequest{" +
                "documentBase64=" + (documentBase64 != null ? "[BASE64_PRESENT, length=" + documentBase64.length() + "]" : "null") +
                ", signatureBase64=" + (signatureBase64 != null ? "[BYTES_PRESENT, length=" + signatureBase64.length() + "]" : "null") +
                ", container=" +(container != null ? container : "null" ) +
                ", signatureFormat=" +(signatureFormat != null ? signatureFormat.toString() : "null" ) +
                ", signatureLevel=" +(signatureLevel != null ? signatureLevel.toString() : "null" ) +
                ", validationTime=" +(validationTime != null ? validationTime.toString() : "null" ) +
                ", trustAnchor=" +(trustAnchor != null ? trustAnchor : "null" )
                + "}";
    }

}