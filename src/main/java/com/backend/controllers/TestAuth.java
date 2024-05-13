package com.backend.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestAuth {
    @RequestMapping("/authtoken/v1")
    public String testAuth(){
        return "oke";
    }
}
