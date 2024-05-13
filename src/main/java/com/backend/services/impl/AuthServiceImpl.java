package com.backend.services.impl;

import java.util.HashSet;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.backend.dtos.LoginDto;
import com.backend.dtos.SignUpDto;
import com.backend.exception.BlogAPIException;
import com.backend.models.Role;
import com.backend.models.User;
import com.backend.repositories.RoleRepository;
import com.backend.repositories.UserRepository;
import com.backend.security.JwtTokenProvider;
import com.backend.services.AuthService;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public String login(LoginDto loginDto) {
        Authentication authentication = authenticationManager
                .authenticate(
                        new UsernamePasswordAuthenticationToken(loginDto.getUsernameOrEmail(), loginDto.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtTokenProvider.generateToken(authentication);

        return token;
    }

    @Override
    public String signUp(SignUpDto signUpDto) {

        // add check for username exists in database
        if (userRepository.existsByUsername(signUpDto.getUsername())) {
            throw new BlogAPIException(HttpStatus.UNAUTHORIZED, "Username is already in use");
        }

        // add check for email exists in database
        if (userRepository.existsByEmail(signUpDto.getEmail())) {
            throw new BlogAPIException(HttpStatus.UNAUTHORIZED, "Email is already in use");
        }

        User user = new User();
        user.setName(signUpDto.getName());
        user.setUsername(signUpDto.getUsername());
        user.setEmail(signUpDto.getEmail());
        user.setPassword(passwordEncoder.encode(signUpDto.getPassword()));

        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName("ROLE_USER").get();
        roles.add(userRole);
        user.setRoles(roles);

        userRepository.save(user);

        return "User registered successfully!.";
    }

}
