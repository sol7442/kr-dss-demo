package kr.dss.demo.model;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import org.springframework.web.multipart.MultipartFile;

public class SignatureDocumentForm extends AbstractSignatureForm implements ContainerDocumentForm {

	public MultipartFile getDocumentToSign() {
		return documentToSign;
	}

	public void setDocumentToSign(MultipartFile documentToSign) {
		this.documentToSign = documentToSign;
	}

	private MultipartFile documentToSign;

	public DSSDocument getToSignDocument() {
		return toSignDocument;
	}

	public void setToSignDocument(DSSDocument toSignDocument) {
		this.toSignDocument = toSignDocument;
	}

	private DSSDocument toSignDocument;

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
