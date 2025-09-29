package kr.dss.demo.model;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import org.springframework.web.multipart.MultipartFile;

public class SignatureDocumentForm extends AbstractSignatureForm implements ContainerDocumentForm {

	//private MultipartFile documentToSign;

	private String fileName;
	private String contentType;
	private byte[] documentBytes;

	@NotNull(message = "{error.signature.packaging.mandatory}")
	private SignaturePackaging signaturePackaging;

	private ASiCContainerType containerType;


	public void setFileName(String fileName){
		this.fileName = fileName;
	}
	public String getFileName(){return this.fileName;}
	public void setContentType(String contentType){
		this.contentType = contentType;
	}
	public String getContenttype(){return this.contentType;}

	public void setDocumentBytes(byte[] documentBytes){
		this.documentBytes = documentBytes;
	}
	public byte[] getDocumentBytes(){return this.documentBytes;}

	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
		this.signaturePackaging = signaturePackaging;
	}

	@Override
	public ASiCContainerType getContainerType() {
		return containerType;
	}

	public void setContainerType(ASiCContainerType containerType) {
		this.containerType = containerType;
	}

	@AssertTrue(message = "{error.to.sign.file.mandatory}")
	public boolean isDocumentToSign() {
		return (documentBytes != null) && (documentBytes.length > 0);
	}

}
