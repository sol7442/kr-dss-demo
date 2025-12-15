package kr.dss.demo.dto;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.*;
import eu.europa.esig.dss.diagnostic.*;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.Date;
import java.util.List;

public class VerifySignedDocResponse {
    //@NotNull(message = "{error.to.verify.file.mandatory}")
    private boolean isValid;
    //private Reports reports;

    private SimpleReport simpleReport = new SimpleReport();
    private DetailedReportItem detailedReport = new DetailedReportItem();
    private DiagnosticTree diagnosticTree = new DiagnosticTree();
    private ValidationReportType etsiValidationReport = new ValidationReportType();

    private String simpleReportStr;
    private String detailedReportStr;
    private String diagnosticTreeStr;
    private String etsiValidationReportStr;

    public VerifySignedDocResponse() {};

    public VerifySignedDocResponse(SimpleReport simple, DetailedReportItem detail, DiagnosticTree diagno, ValidationReportType etsi) {
        this.simpleReport = simple;
        this.detailedReport = detail;
        this.diagnosticTree = diagno;
        this.etsiValidationReport = etsi;
    }

    public void setInvalid() {
        this.isValid = false;
    }
    public void setValid() { this.isValid = true; }
    public void setValid(boolean isValid) { this.isValid = isValid; }

    public void setSimpleReport(SimpleReport report) { this.simpleReport = report; }
    public void setDetailedReport(DetailedReportItem report) { this.detailedReport = report; }
    public void setDiagnosticTree(DiagnosticTree data) { this.diagnosticTree = data; }
    public void setValidationReport(ValidationReportType reportType) { this.etsiValidationReport = reportType; }

    public void setSimpleReportStr(String simpleString) { this.simpleReportStr = simpleString; };
    public void setDetailedReportStr(String detailedString) { this.detailedReportStr = detailedString; };
    public void setDiagnosticTreeStr(String diagnosticTreeStr) { this.diagnosticTreeStr = diagnosticTreeStr; };
    public void setETSIValidationReportStr(String etsiValidationReportStr) { this.etsiValidationReportStr = etsiValidationReportStr; };

    public boolean getIsValid() { return this.isValid; }
    public SimpleReport getSimpleReport() { return this.simpleReport; }
    public DetailedReportItem getDetailedReport() { return this.detailedReport; }
    public DiagnosticTree getDiagnosticTree() { return this.diagnosticTree; }
    public ValidationReportType getETSIValidationReport() { return this.etsiValidationReport; }

    public String getSimpleReportStr() { return this.simpleReportStr;};
    public String getDetailedReportStr() { return this.detailedReportStr;};
    public String getDiagnosticTreeStr() { return this.diagnosticTreeStr;};
    public String getETSIValidationReportStr() { return this.etsiValidationReportStr;};

    public static class SimpleReport {
        private String indication;
        private String message;

        private Date validationTime;
        private String subIndication;
        private List<String> signatureIdList;
        private List<String> timestampIdList;
        private List<String> evidenceRecordIdList;
        private String firstSignatureId;
        private String firstTimestampId;
        private String firstEvidenceRecordId;
        private String documentFileName;
//        private String tokenFileName;
//        private XmlCertificateChain certificateChain;
//        private List<Message> validationErrors;
//        private List<Message> validationWarnings;
//        private List<Message> validationInfo;
//        private List<Message> qualificationErrors;
//        private List<Message> qualificationWarnings;
//        private List<Message> qualificationInfo;
//        private SignatureQualification signatureQualification;
        private SignatureLevel signatureFormat;
        private Date bestSignatureTime;
        private Date signingTime;
        private Date evidenceRecordPOE;
        private ASiCContainerType containerType;

        public String getIndication() { return indication; }
        public void setIndication(String indication) { this.indication = indication; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public Date getValidationTime() { return validationTime; }
        public void setValidationTime(Date validationTime) { this.validationTime = validationTime; }
        public String getSubIndication() { return subIndication; }
        public void setSubIndication(String subIndication) { this.subIndication = subIndication; }
        public List<String> getSignatureIdList() { return signatureIdList; }
        public void setSignatureIdList(List<String> signatureIdList) { this.signatureIdList = signatureIdList; }
        public List<String> getTimestampIdList() { return timestampIdList; }
        public void setTimestampIdList(List<String> timestampIdList) { this.timestampIdList = timestampIdList; }
        public List<String> getEvidenceRecordIdList() { return evidenceRecordIdList; }
        public void setEvidenceRecordIdList(List<String> evidenceRecordIdList) { this.evidenceRecordIdList = evidenceRecordIdList; }
        public String getFirstSignatureId() { return firstSignatureId; }
        public void setFirstSignatureId(String firstSignatureId) { this.firstSignatureId = firstSignatureId; }
        public String getFirstTimestampId() { return firstTimestampId; }
        public void setFirstTimestampId(String firstTimestampId) { this.firstTimestampId = firstTimestampId; }
        public String getFirstEvidenceRecordId() { return firstEvidenceRecordId; }
        public void setFirstEvidenceRecordId(String firstEvidenceRecordId) { this.firstEvidenceRecordId = firstEvidenceRecordId; }
        public String getDocumentFileName() { return documentFileName; }
        public void setDocumentFileName(String documentFileName) { this.documentFileName = documentFileName; }
//        public String getTokenFileName() { return tokenFileName; }
//        public void setTokenFileName(String tokenFileName) { this.tokenFileName = tokenFileName; }
//        public XmlCertificateChain getCertificateChain() { return certificateChain; }
//        public void setCertificateChain(XmlCertificateChain certificateChain) { this.certificateChain = certificateChain; }
//        public List<Message> getValidationErrors() { return validationErrors; }
//        public void setValidationErrors(List<Message> validationErrors) { this.validationErrors = validationErrors; }
//        public List<Message> getValidationWarnings() { return validationWarnings; }
//        public void setValidationWarnings(List<Message> validationWarnings) { this.validationWarnings = validationWarnings; }
//        public List<Message> getValidationInfo() { return validationInfo; }
//        public void setValidationInfo(List<Message> validationInfo) { this.validationInfo = validationInfo; }
//        public List<Message> getQualificationErrors() { return qualificationErrors; }
//        public void setQualificationErrors(List<Message> qualificationErrors) { this.qualificationErrors = qualificationErrors; }
//        public List<Message> getQualificationWarnings() { return qualificationWarnings; }
//        public void setQualificationWarnings(List<Message> qualificationWarnings) { this.qualificationWarnings = qualificationWarnings; }
//        public List<Message> getQualificationInfo() { return qualificationInfo; }
//        public void setQualificationInfo(List<Message> qualificationInfo) { this.qualificationInfo = qualificationInfo; }
//        public SignatureQualification getSignatureQualification() { return signatureQualification; }
//        public void setSignatureQualification(SignatureQualification signatureQualification) { this.signatureQualification = signatureQualification; }
        public SignatureLevel getSignatureFormat() { return signatureFormat; }
        public void setSignatureFormat(SignatureLevel signatureFormat) { this.signatureFormat = signatureFormat; }
        public Date getBestSignatureTime() { return bestSignatureTime; }
        public void setBestSignatureTime(Date bestSignatureTime) { this.bestSignatureTime = bestSignatureTime; }
        public Date getSigningTime() { return signingTime; }
        public void setSigningTime(Date signingTime) { this.signingTime = signingTime; }
        public Date getEvidenceRecordPOE() { return evidenceRecordPOE; }
        public void setEvidenceRecordPOE(Date evidenceRecordPOE) { this.evidenceRecordPOE = evidenceRecordPOE; }
        public ASiCContainerType getContainerType() { return containerType; }
        public void setContainerType(ASiCContainerType containerType) { this.containerType = containerType; }
    }

    public static class DetailedReportItem {
        private String name;
        private String status;
        private String message;

//        private String basicBuildingBlocksIndication;
//        private String basicBuildingBlocksSubIndication;
//        private List<String> basicBuildingBlocksCertChain;
//        private XmlBasicBuildingBlocks basicBuildingBlocks; //too long
        private int basicBuildingBlocksNumber;
//        private String basicBuildingBlocksSignatureId;
        private List<String> signatureIds;
        private String firstSignatureId;
        private String firstTimestampId;
//        private List<String> timeStampIds;
        private String firstEvidenceRecordId;
        private List<String> evidenceRecordIds;
        private List<String> revocationIds;
        private Date bestSignatureTime;
        private XmlProofOfExistence bestProofOfExistence;
//        private Date evidenceRecordLowestPOETime;
//        private SignatureQualification signatureQualification;
//        private TimestampQualification timestampQualification;
//        private TimestampQualification timestampQualificationAtTstGenerationTime;
//        private TimestampQualification timestampQualificationAtBestPoeTime;
//        private TimestampQualification timestampQualificationAtValidationTime;
//        private XmlValidationTimestampQualification xmlValidationTimestampQualification;
//        private XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp;
        private XmlValidationProcessArchivalDataTimestamp xmlValidationProcessArchivalDataTimestamp;
//        private XmlTimestamp xmlTimestamp;
//        private XmlSignature xmlSignature;
//        private XmlCertificate xmlCertificate;
        private List<XmlSignature> signatures;
        private List<XmlTimestamp> independentTimestamp;
        private List<eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord> independentEvidenceRecords;
        private List<XmlCertificate> certificates;
//        private XmlTLAnalysis tlAnalysis;
//        private boolean isCertificationValidation;
//        private CertificateQualification certificateQualificationAtIssuance;
//        private CertificateQualification certificateQualificationAtValidation;
//        private CertificateQualification certificateQualificationAtTime;
        private XmlConclusion finalConclusion;
        private String finalIndication;
        private String finalSubIndication;
//        private XmlSubXCV signingCertificate;
//        private String basicValidationIndication;
//        private String basicValidationSubIndication;
//        private String basicTimestampValidationIndication;
//        private String basicTimestampValidationSubIndication;
//        private String archiveDataTimestampValidationIndication;
//        private String archiveDataTimestampValidationSubIndication;
//        private String evidenceRecordValidationIndication;
//        private String evidenceRecordValidationSubIndication;
//        private String longTermValidationIndication;
//        private String longTermValidationSubIndication;
//        private String archiveDataValidationIndication;
//        private String archiveDataValidationSubIndication;
//        private XmlConclusion certificateXCVConclusion;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }

//        public String getBasicBuildingBlocksIndication() { return basicBuildingBlocksIndication; }
//        public void setBasicBuildingBlocksIndication(String basicBuildingBlocksIndication) { this.basicBuildingBlocksIndication = basicBuildingBlocksIndication;}
//        public String getBasicBuildingBlocksSubIndication() { return basicBuildingBlocksSubIndication; }
//        public void setBasicBuildingBlocksSubIndication(String basicBuildingBlocksSubIndication) { this.basicBuildingBlocksSubIndication = basicBuildingBlocksSubIndication; }
//        public List<String> getBasicBuildingBlocksCertChain() { return basicBuildingBlocksCertChain; }
//        public void setBasicBuildingBlocksCertChain(List<String> basicBuildingBlocksCertChain) { this.basicBuildingBlocksCertChain = basicBuildingBlocksCertChain; }
//        public XmlBasicBuildingBlocks getBasicBuildingBlocks() { return basicBuildingBlocks; }
//        public void setBasicBuildingBlocks(XmlBasicBuildingBlocks basicBuildingBlocks) { this.basicBuildingBlocks = basicBuildingBlocks; }
        public int getBasicBuildingBlocksNumber() { return basicBuildingBlocksNumber; }
        public void setBasicBuildingBlocksNumber(int basicBuildingBlocksNumber) { this.basicBuildingBlocksNumber = basicBuildingBlocksNumber; }
//        public String getBasicBuildingBlocksSignatureId() { return basicBuildingBlocksSignatureId; }
//        public void setBasicBuildingBlocksSignatureId(String basicBuildingBlocksSignatureId) { this.basicBuildingBlocksSignatureId = basicBuildingBlocksSignatureId; }
        public List<String> getSignatureIds() { return signatureIds; }
        public void setSignatureIds(List<String> signatureIds) { this.signatureIds = signatureIds; }
        public String getFirstSignatureId() { return firstSignatureId; }
        public void setFirstSignatureId(String firstSignatureId) { this.firstSignatureId = firstSignatureId; }
        public String getFirstTimestampId() { return firstTimestampId; }
        public void setFirstTimestampId(String firstTimestampId) { this.firstTimestampId = firstTimestampId; }
//        public List<String> getTimeStampIds() { return timeStampIds; }
//        public void setTimeStampIds(List<String> timeStampIds) { this.timeStampIds = timeStampIds; }
        public String getFirstEvidenceRecordId() { return firstEvidenceRecordId; }
        public void setFirstEvidenceRecordId(String firstEvidenceRecordId) { this.firstEvidenceRecordId = firstEvidenceRecordId; }
        public List<String> getEvidenceRecordIds() { return evidenceRecordIds; }
        public void setEvidenceRecordIds(List<String> evidenceRecordIds) { this.evidenceRecordIds = evidenceRecordIds; }
        public List<String> getRevocationIds() { return revocationIds; }
        public void setRevocationIds(List<String> revocationIds) { this.revocationIds = revocationIds; }
        public Date getBestSignatureTime() { return bestSignatureTime; }
        public void setBestSignatureTime(Date bestSignatureTime) { this.bestSignatureTime = bestSignatureTime; }
        public XmlProofOfExistence getBestProofOfExistence() { return bestProofOfExistence; }
        public void setBestProofOfExistence(XmlProofOfExistence bestProofOfExistence) { this.bestProofOfExistence = bestProofOfExistence; }
//        public Date getEvidenceRecordLowestPOETime() { return evidenceRecordLowestPOETime; }
//        public void setEvidenceRecordLowestPOETime(Date evidenceRecordLowestPOETime) { this.evidenceRecordLowestPOETime = evidenceRecordLowestPOETime; }
//        public XmlEvidenceRecord getXmlEvidenceRecord() { return xmlEvidenceRecord; }
//        public void setXmlEvidenceRecord(XmlEvidenceRecord xmlEvidenceRecord) { this.xmlEvidenceRecord = xmlEvidenceRecord; }
//        public SignatureQualification getSignatureQualification() { return signatureQualification; }
//        public void setSignatureQualification(SignatureQualification signatureQualification) { this.signatureQualification = signatureQualification; }
//        public TimestampQualification getTimestampQualification() { return timestampQualification; }
//        public void setTimestampQualification(TimestampQualification timestampQualification) { this.timestampQualification = timestampQualification; }
//        public TimestampQualification getTimestampQualificationAtTstGenerationTime() { return timestampQualificationAtTstGenerationTime; }
//        public void setTimestampQualificationAtTstGenerationTime(TimestampQualification timestampQualificationAtTstGenerationTime) { this.timestampQualificationAtTstGenerationTime = timestampQualificationAtTstGenerationTime; }
//        public TimestampQualification getTimestampQualificationAtBestPoeTime() { return timestampQualificationAtBestPoeTime; }
//        public void setTimestampQualificationAtBestPoeTime(TimestampQualification timestampQualificationAtBestPoeTime) { this.timestampQualificationAtBestPoeTime = timestampQualificationAtBestPoeTime; }
//        public TimestampQualification getTimestampQualificationAtValidationTime() { return timestampQualificationAtValidationTime; }
//        public void setTimestampQualificationAtValidationTime(TimestampQualification timestampQualificationAtValidationTime) { this.timestampQualificationAtValidationTime = timestampQualificationAtValidationTime; }
//        public XmlValidationTimestampQualification getXmlValidationTimestampQualification() { return xmlValidationTimestampQualification; }
//        public void setXmlValidationTimestampQualification(XmlValidationTimestampQualification xmlValidationTimestampQualification) { this.xmlValidationTimestampQualification = xmlValidationTimestampQualification; }
//        public XmlValidationProcessBasicTimestamp getXmlValidationProcessBasicTimestamp() { return xmlValidationProcessBasicTimestamp; }
//        public void setXmlValidationProcessBasicTimestamp(XmlValidationProcessBasicTimestamp xmlValidationProcessBasicTimestamp) { this.xmlValidationProcessBasicTimestamp = xmlValidationProcessBasicTimestamp; }
        public XmlValidationProcessArchivalDataTimestamp getXmlValidationProcessArchivalDataTimestamp() { return xmlValidationProcessArchivalDataTimestamp; }
        public void setXmlValidationProcessArchivalDataTimestamp(XmlValidationProcessArchivalDataTimestamp xmlValidationProcessArchivalDataTimestamp) { this.xmlValidationProcessArchivalDataTimestamp = xmlValidationProcessArchivalDataTimestamp; }
//        public XmlTimestamp getXmlTimestamp() { return xmlTimestamp; }
//        public void setXmlTimestamp(XmlTimestamp xmlTimestamp) { this.xmlTimestamp = xmlTimestamp; }
//        public XmlSignature getXmlSignature() { return xmlSignature; }
//        public void setXmlSignature(XmlSignature xmlSignature) { this.xmlSignature = xmlSignature; }
//        public XmlCertificate getXmlCertificate() { return xmlCertificate; }
//        public void setXmlCertificate(XmlCertificate xmlCertificate) { this.xmlCertificate = xmlCertificate; }
        public List<XmlSignature> getSignatures() { return signatures; }
        public void setSignatures(List<XmlSignature> signatures) { this.signatures = signatures; }
        public List<XmlTimestamp> getIndependentTimestamp() { return independentTimestamp; }
        public void setIndependentTimestamp(List<XmlTimestamp> independentTimestamp) { this.independentTimestamp = independentTimestamp; }
        public List<eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord> getIndependentEvidenceRecords() { return independentEvidenceRecords; }
        public void setIndependentEvidenceRecords(List<eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord> independentEvidenceRecords) { this.independentEvidenceRecords = independentEvidenceRecords; }
        public List<XmlCertificate> getCertificates() { return certificates; }
        public void setCertificates(List<XmlCertificate> certificates) { this.certificates = certificates; }
//        public XmlTLAnalysis getTlAnalysis() { return tlAnalysis; }
//        public void setTlAnalysis(XmlTLAnalysis tlAnalysis) { this.tlAnalysis = tlAnalysis; }
//        public boolean isCertificationValidation() { return isCertificationValidation; }
//        public void setCertificationValidation(boolean certificationValidation) { isCertificationValidation = certificationValidation; }
//        public CertificateQualification getCertificateQualificationAtIssuance() { return certificateQualificationAtIssuance; }
//        public void setCertificateQualificationAtIssuance(CertificateQualification certificateQualificationAtIssuance) { this.certificateQualificationAtIssuance = certificateQualificationAtIssuance; }
//        public CertificateQualification getCertificateQualificationAtValidation() { return certificateQualificationAtValidation; }
//        public void setCertificateQualificationAtValidation(CertificateQualification certificateQualificationAtValidation) { this.certificateQualificationAtValidation = certificateQualificationAtValidation; }
//        public CertificateQualification getCertificateQualificationAtTime() { return certificateQualificationAtTime; }
//        public void setCertificateQualificationAtTime(CertificateQualification certificateQualificationAtTime) { this.certificateQualificationAtTime = certificateQualificationAtTime; }
        public XmlConclusion getFinalConclusion() { return finalConclusion; }
        public void setFinalConclusion(XmlConclusion finalConclusion) { this.finalConclusion = finalConclusion; }
        public String getFinalIndication() { return finalIndication; }
        public void setFinalIndication(String finalIndication) { this.finalIndication = finalIndication; }
        public String getFinalSubIndication() { return finalSubIndication; }
        public void setFinalSubIndication(String finalSubIndication) { this.finalSubIndication = finalSubIndication; }
//        public XmlSubXCV getSigningCertificate() { return signingCertificate; }
//        public void setSigningCertificate(XmlSubXCV signingCertificate) { this.signingCertificate = signingCertificate; }
    }
    public static class DiagnosticTree {
        private String name;
        private String status;
        private String message;
        private DiagnosticTree[] children; //tree 구조

        private List<String> signatureIdList;
        private String firstSignatureId;
        private Date firstSignatureDate;
//        private Date signatureDate;
        private SignatureLevel firstSignatureFormat;
//        private SignatureLevel signatureFormat;
        private String firstSignatureDigestAlgorithm;
//        private String signatureDigestAlgorithm;
        private String firstSignatureEncryptionAlgorithm;
//        private String signatureEncryptionAlgorithm;
//        private String signingCertificateId;
//        private boolean isSigningCertificateIdentified;
//        private List<CertificateWrapper> signatureCertificateChain;
//        private List<String> signatureCertificateChainIds;
        private String firstPolicyId;
//        private String policyId;
//        private String policyDescription;
//        private List<String> policyDocumentationReferences;
        private List<String> timestampIdList;
        private List<TimestampWrapper> timestampList;
        private List<SignerDataWrapper> signerDocuments;
//        private String timestampSigningCertificateId;
//        private TimestampType timestampType;
//        private boolean isValidCertificate;
//        private String certificateDN;
//        private String certificateIssuerDN;
//        private String certificateSerialNumber;
//        private RevocationType certificateRevocationSource;
//        private CertificateStatus certificateRevocationStatus;
//        private RevocationReason certificateRevocationReason;
//        private String errorMessage;
        private List<SignatureWrapper> signatures;
        private List<TimestampWrapper> nonEvidenceRecordTimestamps;
        private List<EvidenceRecordWrapper> evidenceRecords;
        private List<CertificateWrapper> usedCertificates;
        private ASiCContainerType containerType;
        private XmlContainerInfo containerInfo;
        private List<XmlTrustedList> trustedLists;
        private Date validationDate;
//        private List<XmlSignerRole> signedAssertionsInFirstSignature;
//        private List<XmlSignerRole> signedAssertions;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }

        public List<String> getSignatureIdList() { return signatureIdList; }
        public void setSignatureIdList(List<String> signatureIdList) { this.signatureIdList = signatureIdList; }
        public String getFirstSignatureId() { return firstSignatureId; }
        public void setFirstSignatureId(String firstSignatureId) { this.firstSignatureId = firstSignatureId; }
        public Date getFirstSignatureDate() { return firstSignatureDate; }
        public void setFirstSignatureDate(Date firstSignatureDate) { this.firstSignatureDate = firstSignatureDate; }
//        public Date getSignatureDate() { return signatureDate; }
//        public void setSignatureDate(Date signatureDate) { this.signatureDate = signatureDate; }
        public SignatureLevel getFirstSignatureFormat() { return firstSignatureFormat; }
        public void setFirstSignatureFormat(SignatureLevel firstSignatureFormat) { this.firstSignatureFormat = firstSignatureFormat; }
//        public SignatureLevel getSignatureFormat() { return signatureFormat; }
//        public void setSignatureFormat(SignatureLevel signatureFormat) { this.signatureFormat = signatureFormat; }
        public String getFirstSignatureDigestAlgorithm() { return firstSignatureDigestAlgorithm; }
        public void setFirstSignatureDigestAlgorithm(String firstSignatureDigestAlgorithm) { this.firstSignatureDigestAlgorithm = firstSignatureDigestAlgorithm; }
//        public String getSignatureDigestAlgorithm() { return signatureDigestAlgorithm; }
//        public void setSignatureDigestAlgorithm(String signatureDigestAlgorithm) { this.signatureDigestAlgorithm = signatureDigestAlgorithm; }
        public String getFirstSignatureEncryptionAlgorithm() { return firstSignatureEncryptionAlgorithm; }
        public void setFirstSignatureEncryptionAlgorithm(String firstSignatureEncryptionAlgorithm) { this.firstSignatureEncryptionAlgorithm = firstSignatureEncryptionAlgorithm; }
//        public String getSignatureEncryptionAlgorithm() { return signatureEncryptionAlgorithm; }
//        public void setSignatureEncryptionAlgorithm(String signatureEncryptionAlgorithm) { this.signatureEncryptionAlgorithm = signatureEncryptionAlgorithm; }
//        public String getSigningCertificateId() { return signingCertificateId; }
//        public void setSigningCertificateId(String signingCertificateId) { this.signingCertificateId = signingCertificateId; }
//        public boolean isSigningCertificateIdentified() { return isSigningCertificateIdentified; }
//        public void setSigningCertificateIdentified(boolean signingCertificateIdentified) { isSigningCertificateIdentified = signingCertificateIdentified; }
//        public List<CertificateWrapper> getSignatureCertificateChain() { return signatureCertificateChain; }
//        public void setSignatureCertificateChain(List<CertificateWrapper> signatureCertificateChain) { this.signatureCertificateChain = signatureCertificateChain; }
//        public List<String> getSignatureCertificateChainIds() { return signatureCertificateChainIds; }
//        public void setSignatureCertificateChainIds(List<String> signatureCertificateChainIds) { this.signatureCertificateChainIds = signatureCertificateChainIds; }
        public String getFirstPolicyId() { return firstPolicyId; }
        public void setFirstPolicyId(String firstPolicyId) { this.firstPolicyId = firstPolicyId; }
//        public String getPolicyId() { return policyId; }
//        public void setPolicyId(String policyId) { this.policyId = policyId; }
//        public String getPolicyDescription() { return policyDescription; }
//        public void setPolicyDescription(String policyDescription) { this.policyDescription = policyDescription; }
//        public List<String> getPolicyDocumentationReferences() { return policyDocumentationReferences; }
//        public void setPolicyDocumentationReferences(List<String> policyDocumentationReferences) { this.policyDocumentationReferences = policyDocumentationReferences; }
        public List<String> getTimestampIdList() { return timestampIdList; }
        public void setTimestampIdList(List<String> timestampIdList) { this.timestampIdList = timestampIdList; }
        public List<TimestampWrapper> getTimestampList() { return timestampList; }
        public void setTimestampList(List<TimestampWrapper> timestampList) { this.timestampList = timestampList; }
        public List<SignerDataWrapper> getSignerDocuments() { return signerDocuments; }
        public void setSignerDocuments(List<SignerDataWrapper> signerDocuments) { this.signerDocuments = signerDocuments; }
//        public String getTimestampSigningCertificateId() { return timestampSigningCertificateId; }
//        public void setTimestampSigningCertificateId(String timestampSigningCertificateId) { this.timestampSigningCertificateId = timestampSigningCertificateId; }
//        public TimestampType getTimestampType() { return timestampType; }
//        public void setTimestampType(TimestampType timestampType) { this.timestampType = timestampType; }
//        public boolean isValidCertificate() { return isValidCertificate; }
//        public void setValidCertificate(boolean validCertificate) { isValidCertificate = validCertificate; }
//        public String getCertificateDN() { return certificateDN; }
//        public void setCertificateDN(String certificateDN) { this.certificateDN = certificateDN; }
//        public String getCertificateIssuerDN() { return certificateIssuerDN; }
//        public void setCertificateIssuerDN(String certificateIssuerDN) { this.certificateIssuerDN = certificateIssuerDN; }
//        public String getCertificateSerialNumber() { return certificateSerialNumber; }
//        public void setCertificateSerialNumber(String certificateSerialNumber) { this.certificateSerialNumber = certificateSerialNumber; }
//        public RevocationType getCertificateRevocationSource() { return certificateRevocationSource; }
//        public void setCertificateRevocationSource(RevocationType certificateRevocationSource) { this.certificateRevocationSource = certificateRevocationSource; }
//        public CertificateStatus getCertificateRevocationStatus() { return certificateRevocationStatus; }
//        public void setCertificateRevocationStatus(CertificateStatus certificateRevocationStatus) { this.certificateRevocationStatus = certificateRevocationStatus; }
//        public RevocationReason getCertificateRevocationReason() { return certificateRevocationReason; }
//        public void setCertificateRevocationReason(RevocationReason certificteRevocationReason) { this.certificateRevocationReason = certificteRevocationReason; }
//        public String getErrorMessage() { return errorMessage; }
//        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
        public List<SignatureWrapper> getSignatures() { return signatures; }
        public void setSignatures(List<SignatureWrapper> signatures) { this.signatures = signatures; }
        public List<TimestampWrapper> getNonEvidenceRecordTimestamps() { return nonEvidenceRecordTimestamps; }
        public void setNonEvidenceRecordTimestamps(List<TimestampWrapper> nonEvidenceRecordTimestamps) { this.nonEvidenceRecordTimestamps = nonEvidenceRecordTimestamps; }
        public List<EvidenceRecordWrapper> getEvidenceRecords() { return evidenceRecords; }
        public void setEvidenceRecords(List<EvidenceRecordWrapper> evidenceRecords) { this.evidenceRecords = evidenceRecords; }
        public List<CertificateWrapper> getUsedCertificates() { return usedCertificates; }
        public void setUsedCertificates(List<CertificateWrapper> usedCertificates) { this.usedCertificates = usedCertificates; }
        public ASiCContainerType getContainerType() { return containerType; }
        public void setContainerType(ASiCContainerType containerType) { this.containerType = containerType; }
        public XmlContainerInfo getContainerInfo() { return containerInfo; }
        public void setContainerInfo(XmlContainerInfo containerInfo) { this.containerInfo = containerInfo; }
        public List<XmlTrustedList> getTrustedLists() { return trustedLists; }
        public void setTrustedLists(List<XmlTrustedList> trustedLists) { this.trustedLists = trustedLists; }
        public Date getValidationDate() { return validationDate; }
        public void setValidationDate(Date validationDate) { this.validationDate = validationDate;}
    }

    //---------------------------------------
//    public void setMessage(String status, String message) {
//        this.simpleReport.indication = status;
//        this.simpleReport.message = message;
//
//        this.detailedReport.name = "[detailedReport]"; //+date : unique-report-name
//        this.detailedReport.status = status;
//        this.detailedReport.message = message;
//
//        this.diagnosticTree.name = "[diagnosticTree]"; //+date : unique-report-name
//        this.diagnosticTree.status = status;
//        this.diagnosticTree.message = message;
//    }
    //---------------------------------------
    public void setSimpleReport(Reports reports) {
        eu.europa.esig.dss.simplereport.SimpleReport report = reports.getSimpleReport();

        String tokenId = reports.getSimpleReport().getFirstSignatureId();
        this.simpleReport.indication = String.valueOf(report.getIndication(tokenId));
//        this.simpleReport.message = String.valueOf(report.getSubIndication(tokenId));
        this.simpleReport.validationTime = report.getValidationTime();
        this.simpleReport.subIndication = String.valueOf(report.getSubIndication(tokenId));
        this.simpleReport.signatureIdList = report.getSignatureIdList();
        this.simpleReport.timestampIdList = report.getTimestampIdList();
        this.simpleReport.evidenceRecordIdList = report.getEvidenceRecordIdList();
        this.simpleReport.firstSignatureId = report.getFirstSignatureId();
        this.simpleReport.firstTimestampId = report.getFirstTimestampId();
        this.simpleReport.firstEvidenceRecordId = report.getFirstEvidenceRecordId();
        this.simpleReport.documentFileName = report.getDocumentFilename();
//        this.simpleReport.tokenFileName = report.getTokenFilename(tokenId);
    }
    public void setDetailedReport(Reports reports) {
        DetailedReport report = reports.getDetailedReport();

        String tokenId = report.getFirstSignatureId();

        this.detailedReport.basicBuildingBlocksNumber = report.getBasicBuildingBlocksNumber();
//        this.detailedReport.basicBuildingBlocks = report.getBasicBuildingBlockById(tokenId);
//        this.detailedReport.basicBuildingBlocksCertChain = report.getBasicBuildingBlocksCertChain(tokenId);

        this.detailedReport.signatureIds = report.getSignatureIds();
        this.detailedReport.evidenceRecordIds = report.getEvidenceRecordIds();
        this.detailedReport.revocationIds = report.getRevocationIds();
        this.detailedReport.signatures = report.getSignatures();
        this.detailedReport.independentTimestamp = report.getIndependentTimestamps();
        this.detailedReport.independentEvidenceRecords = report.getIndependentEvidenceRecords();
        this.detailedReport.certificates = report.getCertificates();

        this.detailedReport.firstSignatureId = report.getFirstSignatureId();
        this.detailedReport.firstTimestampId = report.getFirstTimestampId();
        this.detailedReport.firstEvidenceRecordId = report.getFirstEvidenceRecordId();
        this.detailedReport.bestSignatureTime = report.getBestSignatureTime(this.detailedReport.firstSignatureId);
        this.detailedReport.bestProofOfExistence = report.getBestProofOfExistence(this.detailedReport.firstSignatureId);
        
        this.detailedReport.finalIndication = String.valueOf(report.getFinalIndication(tokenId));
        this.detailedReport.finalSubIndication = String.valueOf(report.getFinalSubIndication(tokenId));
        this.detailedReport.finalConclusion = report.getFinalConclusion(tokenId);

    }
    public void setDiagnosticDate(Reports reports) {
        DiagnosticData report = reports.getDiagnosticData();

        this.diagnosticTree.name = report.getDocumentName();
        this.diagnosticTree.trustedLists = report.getTrustedLists();
        this.diagnosticTree.signatureIdList = report.getSignatureIdList();
        this.diagnosticTree.timestampIdList = report.getTimestampIdList();
        this.diagnosticTree.timestampList = report.getTimestampList();
        this.diagnosticTree.signerDocuments = report.getAllSignerDocuments();
        this.diagnosticTree.evidenceRecords = report.getEvidenceRecords();
        this.diagnosticTree.nonEvidenceRecordTimestamps = report.getNonEvidenceRecordTimestamps();
        this.diagnosticTree.signatures =report.getSignatures();
        this.diagnosticTree.usedCertificates =report.getUsedCertificates();
        this.diagnosticTree.validationDate = report.getValidationDate();

        this.diagnosticTree.firstSignatureFormat = report.getFirstSignatureFormat();
        this.diagnosticTree.firstPolicyId = report.getFirstPolicyId();
        this.diagnosticTree.firstSignatureId = report.getFirstSignatureId();
        this.diagnosticTree.firstSignatureDate = report.getFirstSignatureDate();
        this.diagnosticTree.firstSignatureDigestAlgorithm = String.valueOf(report.getFirstSignatureDigestAlgorithm());
        this.diagnosticTree.firstSignatureEncryptionAlgorithm = String.valueOf(report.getFirstSignatureEncryptionAlgorithm());

        this.diagnosticTree.containerType = report.getContainerType();
        this.diagnosticTree.containerInfo = report.getContainerInfo();
    }
    public void setEtsiValidationReport(Reports reports) {
        ValidationReportType report = reports.getEtsiValidationReportJaxb();

    }

    public void setReports(Reports reports) {
        this.simpleReportStr = reports.getXmlSimpleReport();
        this.detailedReportStr = reports.getXmlDetailedReport();
        this.diagnosticTreeStr = reports.getXmlDiagnosticData();

        // 잠시 주석 - report depth 너무 깊음
        // this.etsiValidationReportStr = reports.getXmlValidationReport();
        // this.etsiValidationReport.setSignatureValidator(reports.getEtsiValidationReportJaxb().getSignatureValidator());
        // this.etsiValidationReport.setSignatureValidationObjects(reports.getEtsiValidationReportJaxb().getSignatureValidationObjects());
        // this.etsiValidationReport.setSignature(reports.getEtsiValidationReportJaxb().getSignature());
    }
}
