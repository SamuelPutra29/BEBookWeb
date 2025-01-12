package com.example.book_api.controller;

import com.example.book_api.service.AuthService;
import com.example.book_api.model.User;
import com.example.book_api.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    // User Registration
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        authService.registerUser(user.getUsername(), user.getPassword(), user.getEmail());
        return ResponseEntity.ok("User registered successfully!");
    }

    // User Login
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User user) {  // Use @RequestBody to get the entire user object
        try {
            User authenticatedUser = authService.authenticateUser(user.getUsername(), user.getPassword());
            String token = jwtUtil.generateToken(authenticatedUser.getUsername());
            return ResponseEntity.ok(token);  // Return JWT token on successful login
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }
    }
}
