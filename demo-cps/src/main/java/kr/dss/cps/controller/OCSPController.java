package kr.dss.cps.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import kr.dss.cps.services.OCSPService;

@RestController
@RequestMapping("/ocsp")
public class OCSPController {
	
	@Autowired
	private OCSPService ocspService;


	@PostMapping(consumes = "application/ocsp-request", produces = "application/ocsp-response")
	public ResponseEntity<byte[]> checkCertificateStatus(@RequestBody byte[] requestBytes) {
		try {
			byte[] responseBytes = ocspService.generateOcspResponse(requestBytes);

			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.parseMediaType("application/ocsp-response"));
			return new ResponseEntity<>(responseBytes, headers, HttpStatus.OK);

		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).contentType(MediaType.TEXT_PLAIN)
					.body(("OCSP server error: " + e.getMessage()).getBytes());
		}
	}

}
