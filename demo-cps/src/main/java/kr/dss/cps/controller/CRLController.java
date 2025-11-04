package kr.dss.cps.controller;


import kr.dss.cps.services.OCSPService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/crl")
public class CRLController {

    @Autowired
    private OCSPService ocspService;

    @GetMapping(consumes= "application/crl")
    public ResponseEntity<byte[]> checkCRL() {
        //search CRL
        byte[] responseBytes = ocspService.searchCRL();

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("application/crl"));

        //return Certificate Revocation Lists
        return new ResponseEntity<>(responseBytes, headers, HttpStatus.OK);
    }
}
