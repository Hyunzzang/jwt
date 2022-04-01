package com.example.jwt.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@Slf4j
@ControllerAdvice
public class ExceptionHandler {

    @ResponseBody
    @ResponseStatus
    public ResponseEntity handelException(Exception e) {
        log.info("::: ExceptionHandler - message: {}", e.getMessage());
        return ResponseEntity
                .status(HttpStatus.EXPECTATION_FAILED)
                .body(e.getMessage());
    }
}
