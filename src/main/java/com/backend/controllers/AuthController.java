package com.backend.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.backend.dtos.JWTAuthResponse;
import com.backend.dtos.LoginDto;
import com.backend.dtos.SignUpDto;
import com.backend.services.AuthService;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final  AuthService authService;

    // Build Login REST API
    @PostMapping(value = { "/login", "/signin" })
    public ResponseEntity<JWTAuthResponse> login(@RequestBody LoginDto loginDto) throws Exception {
        String token = authService.login(loginDto);

        JWTAuthResponse jwtAuthResponse = new JWTAuthResponse();
        jwtAuthResponse.setAccessToken(token);

        return ResponseEntity.ok(jwtAuthResponse);
    }

    // Build Register REST API
    @PostMapping(value = { "/register", "/signup" })
    public ResponseEntity<String> register(@RequestBody SignUpDto signUpDto) throws Exception {
        String response = authService.signUp(signUpDto);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }
}
