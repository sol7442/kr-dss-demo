package kr.dss.cps.controller;


import kr.dss.cps.services.OCSPService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger LOG = LoggerFactory.getLogger(CRLController.class);

    @GetMapping(consumes= "application/crl")
    public ResponseEntity<byte[]> checkCRL() {
        try {
            //search CRL
            byte[] responseBytes = ocspService.searchCRL();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/crl"));

            LOG.info("CRL response generated ({} bytes)", responseBytes.length);

            //return Certificate Revocation Lists
            return new ResponseEntity<>(responseBytes, headers, HttpStatus.OK);
        } catch (Exception e) {
            LOG.error("CRL Error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).contentType(MediaType.TEXT_PLAIN)
                    .body(("CRL error : " + e.getMessage()).getBytes());
        }
    }
}
