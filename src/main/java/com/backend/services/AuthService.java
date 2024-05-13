package com.backend.services;

import com.backend.dtos.LoginDto;
import com.backend.dtos.SignUpDto;

public interface AuthService {

    String login(LoginDto loginDto);

    String signUp(SignUpDto signUpDto);
}
