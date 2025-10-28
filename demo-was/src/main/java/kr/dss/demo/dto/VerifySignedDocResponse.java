package kr.dss.demo.dto;

//import eu.europa.esig.dss.detailedreport.DetailedReport;
//import eu.europa.esig.dss.diagnostic.DiagnosticData;
//import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

//2025.10.10_sujin : Set Verify Response DTO for KR-DSS.
public class VerifySignedDocResponse {
    //@NotNull(message = "{error.to.verify.file.mandatory}")
    private boolean isValid;

    private SimpleReport simpleReport = new SimpleReport();
    private DetailedReportItem detailedReport = new DetailedReportItem();
    private DiagnosticTree diagnosticTree = new DiagnosticTree();
    private ValidationReportType etsiValidationReport = new ValidationReportType();

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

    public boolean getIsValid() { return this.isValid; }
    public SimpleReport getSimpleReport() { return this.simpleReport; }
    public DetailedReportItem getDetailedReport() { return this.detailedReport; }
    public DiagnosticTree getDiagnosticTree() { return this.diagnosticTree; }
    public ValidationReportType getEtsiValidationReport() { return this.etsiValidationReport; }


    public static class SimpleReport {
        private String indication;
        private String message;
    }
    public static class DetailedReportItem {
        private String name;
        private String status;
        private String message;
    }
    public static class DiagnosticTree {
        private String name;
        private String status;
        private String message;
        private DiagnosticTree[] children; //tree 구조
    }

    public VerifySignedDocResponse setMessage(String status, String message) {
        this.simpleReport.indication = status;
        this.simpleReport.message = message;

        this.detailedReport.name = "[detailedReport]"; //+date : unique-report-name
        this.detailedReport.status = status;
        this.detailedReport.message = message;

        this.diagnosticTree.name = "[diagnosticTree]"; //+date : unique-report-name
        this.diagnosticTree.status = status;
        this.diagnosticTree.message = message;

        return this;
    }

    public void printSimpleReport() {

    }
    public void printDetailedReport() {

    }
    public void printDiagnosticTree() {

    }
    public void printETSIValidationReport() {

    }

}
