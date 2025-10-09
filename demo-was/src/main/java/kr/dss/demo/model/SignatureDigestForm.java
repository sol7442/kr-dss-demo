package kr.dss.demo.model;



import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public class SignatureDigestForm extends AbstractSignatureForm {

	@NotNull(message = "{error.document.name.mandatory}")
	private String documentName;


	@NotEmpty(message = "{error.to.sign.digest.mandatory}")
	private String digestToSign;
	
	public String getDocumentName() {
		return documentName;
	}

	public void setDocumentName(String documentName) {
		this.documentName = documentName;
	}

	public String getDigestToSign() {
		return digestToSign;
	}

	public void setDigestToSign(String digestToSign) {
		this.digestToSign = digestToSign;
	}
	
}
