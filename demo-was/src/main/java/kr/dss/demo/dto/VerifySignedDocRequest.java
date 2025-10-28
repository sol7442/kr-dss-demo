package kr.dss.demo.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import jakarta.validation.constraints.NotNull;

import java.util.List;

// Set Verify Request DTO for KR-DSS.
public class VerifySignedDocRequest {
    @JsonProperty("documentBase64")
    private String documentBase64;

    @JsonProperty("signatureBase64")
    @NotNull (message = "{error.to.verify.signedFile.empty}")
    private String signatureBase64;

    @JsonProperty("policy")
    private PolicyProperties policy;
    //---------------------------------------
    public VerifySignedDocRequest() {}

    public VerifySignedDocRequest(String signature) {
        this.signatureBase64 = signature;
    }
    public String getSignature() { return this.signatureBase64; }
    public void setPolicy(PolicyProperties policy) { this.policy = policy; }
    public void setDocument(String document) {
        this.documentBase64 = document;
    }
    public PolicyProperties getPolicy() { return this.policy; }
    public String getDocument() { return this.documentBase64; }

    public static class PolicyProperties {
        private String validationModel;
        private String digestAlgorithmRequirement;
        private String validationTime;
        private String trustAnchor;

        //----------------------------------
        //Add Variables - validationLevel, policyFile(optional)
        private ValidationLevel validationLevel;
        private byte[] policyFile;
        //        private byte[] cryptographicSuite;
        //        private byte[] signingCertificate;
        //        private List<byte[]> adjunctCertificates;
        //        private List<byte[]> evidenceRecordFiles;
        //
        //        private boolean includeCertificationTokens;
        //        private boolean includeRevocationTokens;
        //        private boolean includeTimestampTokens;
        //        private boolean includeSemantics;
        //        private boolean includeUserFriendlyIdentifiers = true;
        //----------------------------------

        public String getValidationModel() { return validationModel; }
        public void setValidationModel(String v) { this.validationModel = v; }
        public String getDigestAlgorithmRequirement() { return digestAlgorithmRequirement; }
        public void setDigestAlgorithmRequirement(String v) { this.digestAlgorithmRequirement = v; }
        public String getValidationTime() { return validationTime; }
        public void setValidationTime(String v) { this.validationTime = v; }
        public String getTrustAnchor() { return trustAnchor; }
        public void setTrustAnchor(String v) { this.trustAnchor = v; }

        public void setValidationLevel(ValidationLevel level) { this.validationLevel = level; }
        public ValidationLevel getValidationLevel() { return this.validationLevel; }
        public void setPolicyFile(byte[] policyFile) { this.policyFile = policyFile; }
        public byte[] getPolicyFile() { return this.policyFile; }
    }

    @Override
    public String toString() {
        return "VerifySignedDocRequest{" +
                "documentBase64=" + (documentBase64 != null ? "[BASE64_PRESENT, length=" + documentBase64.length() + "]" : "null") +
                ", signatureBase64=" + (signatureBase64 != null ? "[BYTES_PRESENT, length=" + signatureBase64.length() + "]" : "null") +
                ", policy{"
                + "policy.validationModel=" + policy.validationModel
                + ", policy.digestAlgorithmRequirement=" + policy.digestAlgorithmRequirement
                + ", policy.validationTime=" + policy.validationTime
                + ", policy.trustAnchor=" + policy.trustAnchor + "}"
                + ", policy.validationLevel=" + policy.validationLevel + "}"
                + ", policy.policyFile=" + (policy.policyFile != null ? "[BASE64_PRESENT, length=" + policy.policyFile.length + "]" : "null")
                + "}";
    }

}