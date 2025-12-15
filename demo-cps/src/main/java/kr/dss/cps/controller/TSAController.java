package kr.dss.cps.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import kr.dss.cps.services.TSAService;

@RestController
@RequestMapping("/tsa")
public class TSAController {
    private static final Logger LOG = LoggerFactory.getLogger(TSAController.class);

	@Autowired
    private TSAService tsaService;
	
    @PostMapping(consumes = "application/timestamp-query", produces = "application/timestamp-reply")
    public ResponseEntity<byte[]> handleTimestampRequest(@RequestBody byte[] requestBytes) {
        try {
            byte[] responseBytes = tsaService.generateTimestampResponse(requestBytes);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/timestamp-reply"));
            
            LOG.info("@@@@@TSA response generated ({} bytes)", responseBytes.length);

            return new ResponseEntity<>(responseBytes, headers, HttpStatus.OK);

        } catch (Exception e) {
        	 LOG.error("TSA Error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(("TSA Error: " + e.getMessage()).getBytes());
        }
    }

}
