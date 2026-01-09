package kr.dss.demo.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.*;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.*;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class VerifySignedDocResponse {

    //cleaning files
    private static final long TTL_MILLIS = 60L * 60L * 1000L;           // 1 hour
    private static final long CLEANUP_MIN_INTERVAL = 10L * 60L * 1000L; // 10 min
    private final java.util.concurrent.atomic.AtomicLong lastCleanupAt = new java.util.concurrent.atomic.AtomicLong(0);

    //@NotNull(message = "{error.to.verify.file.mandatory}")
    private boolean isValid;

    private SimpleReport simpleReport = new SimpleReport();
    private List<DetailedReportItem> detailedReport = new ArrayList<>(); //new DetailedReportItem();
    private DiagnosticTree diagnosticTree = new DiagnosticTree();
    private EtsiValidationReportInfo etsiValidationReportInfo = new EtsiValidationReportInfo();

    private String fileName;
    private String downloadUrl;
    // /api/verify/simple_{fileName}
    // /api/verify/detailed_{fileName}
    // /api/verify/diagnostic_{fileName}
    // /api/verify/esti_{fileName}

    public VerifySignedDocResponse() {};

    public VerifySignedDocResponse(SimpleReport simple, DetailedReportItem detail, DiagnosticTree diagno, EtsiValidationReportInfo etsiInfo) {
        this.simpleReport = simple;
        this.detailedReport = (List<DetailedReportItem>) detail; //detail;
        this.diagnosticTree = diagno;
        this.etsiValidationReportInfo = etsiInfo;
        this.fileName = ""; // {signatureFormat}_{digestAlgorithm}_{randomBytes};
        // full file name := "{report_type}_" + fileName
        this.downloadUrl = "/api/verify/reports";
    }
    public void generateFileName(String sigFormat, ValidationLevel validationLevel, Reports reports) {
        DiagnosticData report = reports.getDiagnosticData();
        eu.europa.esig.dss.simplereport.SimpleReport simple = reports.getSimpleReport();
        String firstSigID = simple.getFirstSignatureId();
        SignatureWrapper signatureWrapper = report.getSignatureById(firstSigID);

        final String BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        SecureRandom random = new SecureRandom();

        char[] rand = new char[8];
        for (int i = 0; i < 8; i++) {
            rand[i] = BASE62.charAt(random.nextInt(BASE62.length()));
        }

        String level = "";
        if (validationLevel == ValidationLevel.ARCHIVAL_DATA) {
            level = "LTA";
        } else if (validationLevel == ValidationLevel.LONG_TERM_DATA) {
            level = "LT";
        } else if (validationLevel == ValidationLevel.TIMESTAMPS) {
            level = "T";
        } else {
            level = "B";
        }
        // example: [reportType]_CAdES-Basline-T-SHA512_YYMMDD_RandomNumber(8자리)
        String date = LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String fid = date + "_" + new String(rand);
        this.fileName = sigFormat+"-BASELINE-"+level+"-"+signatureWrapper.getDigestAlgorithm()+"-"+fid+".xml";
        //"["+reportType+"]"+format+"-"+signatureWrapper.getDigestAlgorithm();
        this.downloadUrl= "/api/verify/reports";
    }
    public void downloadReports(Reports reports) throws IOException {
        downloadReport(this.fileName, reports);
    }
    public void setInvalid() {
        this.isValid = false;
    }
    public void setValid() { this.isValid = true; }
    public void setValid(boolean isValid) { this.isValid = isValid; }

    public void setSimpleReport(SimpleReport report) { this.simpleReport = report; }
    public void setDetailedReport(List<DetailedReportItem> report) { this.detailedReport = report; }
    public void setDiagnosticTree(DiagnosticTree data) { this.diagnosticTree = data; }

    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public String getDownloadUrl() { return downloadUrl; }
    public void setDownloadUrl(String downloadUrl) { this.downloadUrl = downloadUrl; }

    public boolean getIsValid() { return this.isValid; }
    public SimpleReport getSimpleReport() { return this.simpleReport; }
    public List<DetailedReportItem> getDetailedReport() { return this.detailedReport; }
    public DiagnosticTree getDiagnosticTree() { return this.diagnosticTree; }

    @JsonProperty("etsiValidationReport")
    public EtsiValidationReportInfo getETSIValidationReport() { return this.etsiValidationReportInfo; }
    public void setValidationReport(EtsiValidationReportInfo reportInfo) { this.etsiValidationReportInfo = reportInfo; }

    public static class SimpleReport {
        private String indication;
        private String message;

        private String subIndication;   // if Indication == TOTAL_PASS, then subIndication = null
                                        // if Indication == TOTAL_FAILED OR INDETERMINATE, then subIndication != null
        private Date validationTime;
        private int signatureCount;

        public String getIndication() { return indication; }
        public void setIndication(String indication) { this.indication = indication; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public Date getValidationTime() { return validationTime; }
        public void setValidationTime(Date validationTime) { this.validationTime = validationTime; }
        public String getSubIndication() { return subIndication; }
        public void setSubIndication(String subIndication) { this.subIndication = subIndication; }
        public void setSignatureCount(int i) { this.signatureCount = i; }
        public int getSignatureCount() { return this.signatureCount; }
    }

    public static class DetailedReportItem {
        private String name;
        private String status;
        private String message;

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
    }
    public static class DiagnosticTree {
        private String name;
        private String status;
        private String message;
        private List<DiagnosticTree> children; //tree 구조

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public List<DiagnosticTree> getChildren() { return children; }
        public void setChildren(List<DiagnosticTree> children) { this.children = children; }
    }

    public static class EtsiValidationReportInfo {
        private boolean available;
        private String message;

        private String mainIndication;
        private String validationTime;
        private String poeTime; // bestSignatureTime;
        private String policy;
        private String algorithm;
        private String signerInfo;
        private String cert;
        private String certNotAfter;
        private String timeStampEvidence;

        public boolean isAvailable() { return available; }
        public void setAvailable(boolean available) { this.available = available; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }

        public String getMainIndication() { return mainIndication; }
        public void setMainIndication(String mainIndication) { this.mainIndication = mainIndication; }
        public String getValidationTime() { return validationTime; }
        public void setValidationTime(String validationTime) { this.validationTime = validationTime; }
        public String getPoeTime() { return poeTime; }
        public void setPoeTime(String poeTime) { this.poeTime = poeTime; }
        public String getPolicy() { return policy; }
        public void setPolicy(String policy) { this.policy = policy; }
        public String getSignerInfo() { return signerInfo; }
        public void setSignerInfo(String signerInfo) { this.signerInfo = signerInfo; }
        public String getAlgorithm() { return algorithm; }
        public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
        public String getCertNotAfter() { return certNotAfter; }
        public void setCertNotAfter(String notAfter) { this.certNotAfter = notAfter; }
        public String getCert() { return cert; }
        public void setCert(String cert) { this.cert = cert; }
        @JsonProperty("timeStampEvidence")
        public String getTimestampEvidence() { return timeStampEvidence; }
        public void setTimestampEvidence(String timeStampEvidence) { this.timeStampEvidence = timeStampEvidence; }
    }


    public void setSimpleReport(Reports reports) {
        eu.europa.esig.dss.simplereport.SimpleReport report = reports.getSimpleReport();
        String tokenId = report.getFirstSignatureId();

        this.simpleReport.indication = report.getIndication(tokenId) == null ? null : String.valueOf(report.getIndication(tokenId));
        this.simpleReport.subIndication = report.getSubIndication(tokenId) == null ? null : String.valueOf(report.getSubIndication(tokenId));
        this.simpleReport.validationTime = report.getValidationTime();
        this.simpleReport.signatureCount = report.getSignaturesCount();
        int validCount = report.getValidSignaturesCount();
        int invalidCount = this.simpleReport.signatureCount - validCount;

        //message
        if (Indication.TOTAL_PASSED.equals(report.getIndication(tokenId))) {
            this.simpleReport.message =  this.simpleReport.signatureCount+"개의 전자서명이 모두 유효합니다. "
                  + "다만, 신뢰목록(TSL) 기반의 ‘공인/Qualified’ 여부는 판단할 수 없습니다.";
        } else if (Indication.TOTAL_FAILED.equals(report.getIndication(tokenId))) {
            this.simpleReport.message = invalidCount+"개의 전자서명이 유효하지 않습니다.";
        }else if (Indication.INDETERMINATE.equals(report.getIndication(tokenId)) ) {
            this.simpleReport.message = invalidCount+"개의 전자서명에 대하여 검증 결과를 판단할 수 없습니다.";
        } else {
            this.simpleReport.message = "전자서명에 대하여 검증 결과를 판단할 수 없습니다.";
        }

    }
    public void setDetailedReport(String format, String level, Reports reports) {
        DetailedReport report = reports.getDetailedReport();
        List<String> sigIds = report.getSignatureIds(); //tokenIds

        if (sigIds == null || sigIds.isEmpty()) { //not exist signatures
            this.detailedReport = Collections.emptyList();
            return;
        }
        //for detailed info to extract
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        List<DetailedReportItem> items = new ArrayList<>();
        int idx = 1;

        for (String sigId : sigIds) {
            //Extract Indication as Signature Level
            Indication basicInd = report.getBasicValidationIndication(sigId);
            Indication basicTimestampInd = report.getBasicTimestampValidationIndication(sigId);
            Indication longTermInd = report.getLongTermValidationIndication(sigId);
            Indication archiveInd = report.getArchiveDataValidationIndication(sigId);
            Indication archiveTimestampInd = report.getArchiveDataTimestampValidationIndication(sigId);

            //check the corresponding signature level (LTA > LT > T > B)
            Indication ind = firstNonNullIndication(archiveTimestampInd, archiveInd, longTermInd, basicTimestampInd, basicInd);

            //create Detailed Info(item)
            DetailedReportItem item = new DetailedReportItem();
            item.name = "서명 #" + idx + " (" + format + "-BASELINE-" +level + "-" + diagnosticData.getSignatureDigestAlgorithm(sigId) + ")";
            item.status = ind.toString();

            List<String> lines = new ArrayList<String>();
            if (ind == Indication.TOTAL_PASSED || ind == Indication.PASSED) {
                lines.add("• 서명은 " + ind.name() + " 상태이며, 암호 검증 및 서명 형식 검증을 모두 통과했습니다.");
            } else if (ind != null) {
                lines.add("• 서명은 " + ind.name() + " 상태입니다.");
            } else {
                lines.add("• 서명 검증 결과를 판단할 수 없습니다.");
            }

            SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(sigId);
            String signer = signatureWrapper.getSignerName(); //signer
            if (signer != null) {
                lines.add("• 서명자 : " + signer);
            }
//            SignatureLevel format = diagnosticData.getSignatureFormat(sigId); //signature format
            if (format != null) {
                lines.add("• 서명형식 : " + format + "-BASELINE-" +level);
            }
            DigestAlgorithm digestAlgorithm = diagnosticData.getSignatureDigestAlgorithm(sigId); //digest Algorithm
            if (digestAlgorithm != null) {
                lines.add("• 사용 해시/서명 알고리즘 : " + digestAlgorithm.getName());
            }
            CertificateWrapper cert = signatureWrapper.getSigningCertificate(); // signingCertificate info
            if (cert != null) {
                lines.add("• 서명자 인증서 체인 : " + cert.getCertificateChain());
            }

            //generate message
            item.message = joinWithNewline(lines);
            items.add(item);
            idx++;

        }
        this.detailedReport = items;
    }

    public void setDiagnosticData(String format, String level, Reports reports) {
        DiagnosticData report = reports.getDiagnosticData();
        List<String> sigIds = report.getSignatureIdList(); //tokenIds

        eu.europa.esig.dss.simplereport.SimpleReport simple = reports.getSimpleReport();
        DetailedReport detailed = reports.getDetailedReport();

        if (sigIds == null || sigIds.isEmpty()) {
            this.diagnosticTree = null;
            return;
        }

        //Root
        DiagnosticTree node = new DiagnosticTree();
        String firstSigID = simple.getFirstSignatureId();
        SignatureWrapper signatureWrapper = report.getSignatureById(firstSigID);
//        SignatureLevel format = signatureWrapper.getSignatureFormat();
        node.name = "전자서명 검증 트리";
        node.status = String.valueOf(simple.getIndication(firstSigID));
        node.message = format+"-BASELINE-"+level+ " 서명 " + sigIds.size() + "건에 대한 전체 검증 결과";

        //Child Node
        node.children = new ArrayList<DiagnosticTree>();
        int idx = 1;

        for (String sigId : sigIds) {
            //Extract Indication as Signature Level
            Indication basicInd = detailed.getBasicValidationIndication(sigId);
            Indication basicTimestampInd = detailed.getBasicTimestampValidationIndication(sigId);
            Indication longTermInd = detailed.getLongTermValidationIndication(sigId);
            Indication archiveInd = detailed.getArchiveDataValidationIndication(sigId);
            Indication archiveTimestampInd = detailed.getArchiveDataTimestampValidationIndication(sigId);

            //check the corresponding signature level (LTA > LT > T > B)
            Indication ind = firstNonNullIndication(archiveTimestampInd, archiveInd, longTermInd, basicTimestampInd, basicInd);

            SignatureWrapper signWrapper = report.getSignatureById(sigId);
            SignatureLevel sigIdFormat = signWrapper.getSignatureFormat();

            //block 0. sig
            DiagnosticTree sigNode = new DiagnosticTree();
            sigNode.name = "서명 #" + (idx) + " 검증";
            sigNode.status = (ind == null) ? "INDETERMINATE" : ind.toString();

            if (ind == Indication.TOTAL_PASSED || ind == Indication.PASSED) {
                sigNode.message = "형식 검증, 서명값 검증, X.509 인증서 검증을 모두 통과했습니다. (" + ind.toString()+")";
            } else if (ind == Indication.FAILED || ind == Indication.TOTAL_FAILED) {
                sigNode.message = "형식 검증, 서명값 검증, X.509 인증서 검증 과정에서 실패했습니다. (" + ind.toString() +")";
            } else {
                sigNode.message = "형식 검증, 서명값 검증, X.509 인증서 검증 결과를 판단할 수 없습니다. (" + ind.toString() +")";
            }
            sigNode.children = new ArrayList<DiagnosticTree>();

            //block 1. format
            DiagnosticTree formatNode = new DiagnosticTree();
            formatNode.name = "형식 검증(formatChecking)";
            formatNode.status = (basicInd == null) ? "INDETERMINATE" : basicInd.toString();
            formatNode.message = format+"-BASELINE-"+level+" 서명 구조가 규격(ETSI EN 310 Series)에 부합합니다.";
            formatNode.children = null;
            sigNode.children.add(formatNode);

            //block 2. certificate chain
            DiagnosticTree certNode = new DiagnosticTree();
            certNode.name = "서명자 인증서 체인(x509CertificateValidation)";
            certNode.status = (basicInd == null) ? "INDETERMINATE" : basicInd.toString();
            CertificateWrapper cert = signWrapper.getSigningCertificate();
            if (cert != null) {
                certNode.message = "인증서 체인이 정상적으로 검증되었습니다. "+cert.getCertificateChain();
            } else {
                certNode.message = "인증서 체인 정보를 확인할 수 없습니다.";
            }
            certNode.children = null;
            sigNode.children.add(certNode);

            //block 3. Long-term Validation & Archival
            //String s = sigIdFormat.toString().toUpperCase();
            //if (s.contains("LTA")) {
            if (level.contains("LTA")) {
                DiagnosticTree ltNode = new DiagnosticTree();
                ltNode.name = "장기 검증(LT/LTA) 정보";
                ltNode.status = firstNonNullIndication(archiveTimestampInd, archiveInd, longTermInd, null, null).toString();
                //archiveTimestampInd.toString() == null ? null : archiveInd.toString();
                ltNode.message = "아카이브 타임스탬프를 이용한 LTA 검증이 성공하였습니다.";
                ltNode.children = null;
                sigNode.children.add(ltNode);
//            } else if (s.contains("LT")) {
            } else if (level.contains("LT")) {
                DiagnosticTree ltNode = new DiagnosticTree();
                ltNode.name = "장기 검증(LT/LTA) 정보";
                ltNode.status = (longTermInd == null) ? "INDETERMINATE" : longTermInd.toString(); //longTermInd.toString();
                ltNode.message = "장기검증을 위한 검증 자료에 대해 LT 검증이 성공하였습니다.";
                ltNode.children = null;
                sigNode.children.add(ltNode);
            }
            node.children.add(sigNode);
            idx++;
        }
        this.diagnosticTree = node;
    }

    public void setEtsiValidationReport(Reports reports) {
        ValidationReportType report = reports.getEtsiValidationReportJaxb();
        if (report == null) {
            this.etsiValidationReportInfo.available = false;
            return;
        }

        this.etsiValidationReportInfo.available = true;

        // 1. SignatureValidationReport 1개만 추출
        SignatureValidationReportType firstSvr = null;
        List<SignatureValidationReportType> svrList = report.getSignatureValidationReport();
        if (svrList != null && !svrList.isEmpty()) {
            firstSvr = svrList.get(0);
        }

        // 2. 검증 시점 정보(validationTime/POETime)
        if (firstSvr != null && firstSvr.getValidationTimeInfo() != null) {
            ValidationTimeInfoType vti = firstSvr.getValidationTimeInfo();

            // ValidationTime
            Object validationTime = vti.getValidationTime(); // 타입이 XMLGregorianCalendar/String 등일 수 있음
            if (validationTime != null) {
                this.etsiValidationReportInfo.validationTime = String.valueOf(validationTime);
            }

            // POETime (BestSignatureTime > POETime)
            if (vti.getBestSignatureTime() != null) {
                Object poeTime = null;
                try { poeTime = vti.getBestSignatureTime().getPOETime(); } catch (Exception ignored) {}
                if (poeTime == null) {
                    try { poeTime = vti.getBestSignatureTime().getPOETime(); } catch (Exception ignored) {}
                }
                if (poeTime != null) {
                    this.etsiValidationReportInfo.poeTime = String.valueOf(poeTime);
                }
            }
        }

        // 3. 서명자 정보 signerInfo
        if (firstSvr != null) {
            try {
                SignerInformationType signerInformationType = firstSvr.getSignerInformation();
                if (signerInformationType != null && signerInformationType.getSigner() != null) {
                    this.etsiValidationReportInfo.signerInfo = signerInformationType.getSigner();
                }
            } catch (Exception ignored) {}
        }

        // 4. Indication / CryptoInformation 추출
        ValidationStatusType svs = null;
        if (firstSvr != null) {
            try { svs = firstSvr.getSignatureValidationStatus(); } catch (Exception ignored) {}
        }

        if (svs != null) {
            try { // MainIndication
                Object mi = svs.getMainIndication();
                if (mi != null) this.etsiValidationReportInfo.mainIndication = String.valueOf(mi);
            } catch (Exception ignored) {}
            try {// AssociatedValidationReportData -> CryptoInformation
                Object avrdObj = null;
                try {
                    Method m = svs.getClass().getMethod("getAssociatedValidationReportData");
                    Object tmp = m.invoke(svs);
                    avrdObj = tmp;
                } catch (Exception ignored) {}

                CryptoInformationType crypto = null;
                if (avrdObj != null) {
                    if (avrdObj instanceof List) {
                        List<?> avrdList = (List<?>) avrdObj;
                        if (!avrdList.isEmpty() && avrdList.get(0) != null) {
                            Object firstAvrd = avrdList.get(0);
                            try {
                                Method m2 = firstAvrd.getClass().getMethod("getCryptoInformation");
                                Object c = m2.invoke(firstAvrd);
                                if (c instanceof CryptoInformationType) crypto = (CryptoInformationType) c;
                                else if (c != null) crypto = (CryptoInformationType) c;
                            } catch (Exception ignored) {}
                        }
                    }
                    else {
                        try {
                            Method m2 = avrdObj.getClass().getMethod("getCryptoInformation");
                            Object c = m2.invoke(avrdObj);
                            if (c instanceof CryptoInformationType) crypto = (CryptoInformationType) c;
                            else if (c != null) crypto = (CryptoInformationType) c;
                        } catch (Exception ignored) {}
                    }
                }
                if (crypto != null) {
                    Object algo = null;
                    try { algo = crypto.getAlgorithm(); } catch (Exception ignored) {}
                    if (algo != null) this.etsiValidationReportInfo.algorithm = String.valueOf(algo);

                    Object notAfter = null;
                    try { notAfter = crypto.getNotAfter(); } catch (Exception ignored) {}
                    if (notAfter != null) this.etsiValidationReportInfo.certNotAfter = String.valueOf(notAfter);
                }
            } catch (Exception ignored) {}
        }

        // 5. policy 추출
        try {
            Object svp = firstSvr.getSignatureValidationProcess();
            if (svp != null) {
                Object pid = svp.getClass().getMethod("getSignatureValidationProcessID").invoke(svp);
                if (pid != null) {
                    String v = String.valueOf(pid); // urn:etsi:019102:validationprocess:LTA
                    this.etsiValidationReportInfo.policy = v; //policyName
                }
            }
        } catch (Exception ignored) {}

        // if policy == BASIC (DEFAULT), then convert policy contents.
        if (this.etsiValidationReportInfo.policy != null) {
            String p = this.etsiValidationReportInfo.policy.trim().toUpperCase();
            if ("BASIC".equals(p) || "DEFAULT".equals(p)) {
                this.etsiValidationReportInfo.policy = this.etsiValidationReportInfo.policy + " (현재 검증은 기본 정책으로 수행되었습니다.)";
            } else if ("LTA".equals(p)) {
                this.etsiValidationReportInfo.policy = this.etsiValidationReportInfo.policy + " (현재 검증은 LTA에 대한 기본 정책으로 수행되었습니다.)";
            } else if ("LT".equals(p)) {
                this.etsiValidationReportInfo.policy = this.etsiValidationReportInfo.policy + " (현재 검증은 LT에 대한 기본 정책으로 수행되었습니다.)";
            } else if ("T".equals(p)) {
                this.etsiValidationReportInfo.policy = this.etsiValidationReportInfo.policy + " (현재 검증은 T에 대한 기본 정책으로 수행되었습니다.)";
            } else {
                this.etsiValidationReportInfo.policy = this.etsiValidationReportInfo.policy;
            }
        }

        // 6. 검증자 정보(validator Info : TSA/TSP 사용정보)
        ValidationObjectListType voList = report.getSignatureValidationObjects();
        if (voList != null && voList.getValidationObject() != null) {
            List<ValidationObjectType> objects = voList.getValidationObject();

            String tsRef = null;
            String certRef = null;

            for (ValidationObjectType vo : objects) {
                if (vo == null) continue;
                String type = safeObjType(vo);
                if (type == null) continue;

                String t = type.toUpperCase(); // timestamp VOReference 1개만 추출
                if (tsRef == null && (t.contains("TIMESTAMP") || t.contains("TS"))) {
                    try { tsRef = String.valueOf(vo.getId()); } catch (Exception ignored) {}
                    if (tsRef == null || "null".equals(tsRef)) {
                        try { tsRef = String.valueOf(vo.getObjectType()); } catch (Exception ignored) {}
                    }
                } // 인증서(보통 certificate object 중 일부) 1개 - "CERT" 중 1개만 샘플
                if (certRef == null && t.contains("CERT")) {
                    try { certRef = String.valueOf(vo.getId()); } catch (Exception ignored) {}
                    if (certRef == null || "null".equals(certRef)) {
                        try { certRef = String.valueOf(vo.getObjectType()); } catch (Exception ignored) {}
                    }
                }
                if (tsRef != null && certRef != null) break;
            }
            if (tsRef != null) this.etsiValidationReportInfo.timeStampEvidence = tsRef;
            if (certRef != null) this.etsiValidationReportInfo.cert = certRef;
        }

        // 7. message
        String msg;
        String base = "ETSI Validation Report 기준으로 검증 정보(검증 시점, 서명자, 알고리즘 등)를 요약합니다.";
        String qualifiedNote = "신뢰목록(TL/TSL) 기반의 Qualified 여부는 환경 설정에 따라 판단되지 않을 수 있습니다.";

        String main = this.etsiValidationReportInfo.mainIndication;
        if (main == null) {
            msg = base;
        } else if (main.contains("PASSED")) { // TOTAL_PASSED / PASSED
            msg = base + " \n" + qualifiedNote;
        } else if (main.contains("FAILED")) { // TOTAL_FAILED / FAILED
            msg = "검증에 사용된 근거자료는 수집되었으나, 일부 제약 평가 결과로 최종 검증이 실패했습니다. "
                    + "상세 원인은 Detailed/Diagnostic 및 ETSI 원문을 참고하세요.";
        } else { // INDETERMINATE 등
            msg = "검증 근거는 생성되었으나, 일부 증거자료 부족 또는 제약 평가 결과로 최종 판단이 제한됩니다. "
                    + "상세 원인은 Detailed/Diagnostic 및 ETSI 원문을 참고하세요.";
        }
        this.etsiValidationReportInfo.message = msg;

    }

    private String safeObjType(ValidationObjectType vo) {
        Object t = null;
        try { t = vo.getObjectType(); } catch (Exception ignored) {}
        if (t == null) {
            try { t = vo.getObjectType(); } catch (Exception ignored) {}
        }
        if (t == null) return null;
        return String.valueOf(t);
    }
    private List<String> extractTopVoReferences(List<ValidationObjectType> objects, int limit) {
        List<String> out = new ArrayList<String>();
        for (int i = 0; i < objects.size() && out.size() < limit; i++) {
            ValidationObjectType vo = objects.get(i);
            if (vo == null) continue;

            // VOReference가 있는 경우가 많음 (getId / getObjectId / getVOReference 등)
            String ref = null;
            try { ref = String.valueOf(vo.getId()); } catch (Exception ignored) {}
            if (ref == null) {
                try { ref = String.valueOf(vo.getId()); } catch (Exception ignored) {}
            }
            if (ref != null && !"null".equals(ref)) out.add(ref);
        }
        return out;
    }


    private Indication firstNonNullIndication(Indication a, Indication b, Indication c, Indication d, Indication e) {
        if (a != null) return a;
        if (b != null) return b;
        if (c != null) return c;
        if (d != null) return d;
        return e;
    }
    private String joinWithNewline(List<String> lines) {
        if (lines == null || lines.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.size(); i++) {
            if (i > 0) sb.append('\n');
            sb.append(lines.get(i));
        }
        return sb.toString();
    }

    private void downloadReport(String fileName, Reports reports) throws IOException {
        Path reportsDir = Paths.get(System.getProperty("java.io.tmpdir"), "kr-dss", "reports");
        Files.createDirectories(reportsDir);
        //Windows: C:\Users\...\AppData\Local\Temp\kr-dss\reports
        //Linux: /tmp/kr-dss/reports

        cleanupOldReportsIfNeeded(reportsDir); //Delete files 1 hour after file creation

        writeIfNotNull(reportsDir.resolve("[simple]_" + fileName), reports.getXmlSimpleReport());
        writeIfNotNull(reportsDir.resolve("[detailed]_" + fileName), reports.getXmlDetailedReport());
        writeIfNotNull(reportsDir.resolve("[diagnostic]_" + fileName), reports.getXmlDiagnosticData());
        writeIfNotNull(reportsDir.resolve("[etsi]_" + fileName), reports.getXmlValidationReport());
    }
    private void writeIfNotNull(Path path, String xml) throws IOException {
        if (xml == null) return;
        Files.writeString(path, xml, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }
    private void cleanupOldReportsIfNeeded(Path reportBaseDir) {
        long now = System.currentTimeMillis();
        long last = lastCleanupAt.get();

        // skip : (currentTime - file genTime) < 10 min
        if (now - last < CLEANUP_MIN_INTERVAL) return;

        // 동시 요청에 대해 한번만 실행
        if (!lastCleanupAt.compareAndSet(last, now)) return;

        try (var stream = java.nio.file.Files.list(reportBaseDir)) {
            stream
                    .filter(java.nio.file.Files::isRegularFile)
                    .forEach(p -> {
                        try {
                            long lm = java.nio.file.Files.getLastModifiedTime(p).toMillis();
                            if (now - lm >= TTL_MILLIS) {
                                java.nio.file.Files.deleteIfExists(p);
                            }
                        } catch (Exception ignored) {}
                    });
        } catch (Exception ignored) {}
    }


}
