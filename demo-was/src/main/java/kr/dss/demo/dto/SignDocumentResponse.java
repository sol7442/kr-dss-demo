package kr.dss.demo.dto;

import jakarta.validation.constraints.NotNull;

public class SignDocumentResponse {

    @NotNull(message = "{error.to.sign.file.mandatory}")
    private String result;


    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getDocumentBase64() {
        return documentBase64;
    }

    public void setDocumentBase64(String documentBase64) {
        this.documentBase64 = documentBase64;
    }

    private String fileName;
    private String documentBase64;

    public SignDocumentResponse() {}

    public SignDocumentResponse(String result) {
        this.result = result;
    }

    public String getResult() {
        return result;
    }
    public void setResult(String result) {
        this.result = result;
    }




}
