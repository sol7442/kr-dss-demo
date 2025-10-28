package kr.dss.cps.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import kr.dss.cps.services.TASService;

public class TASController {
	@Autowired
    private TASService tsaService;
	
    @PostMapping(consumes = "application/timestamp-query", produces = "application/timestamp-reply")
    public ResponseEntity<byte[]> handleTimestampRequest(@RequestBody byte[] requestBytes) {
        try {
            byte[] responseBytes = tsaService.generateTimestampResponse(requestBytes);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType("application/timestamp-reply"));
            return new ResponseEntity<>(responseBytes, headers, HttpStatus.OK);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(("TSA Error: " + e.getMessage()).getBytes());
        }
    }

}
