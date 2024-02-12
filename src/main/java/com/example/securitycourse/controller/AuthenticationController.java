package com.example.securitycourse.controller;

import com.example.securitycourse.service.AuthenticationUserDetailService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;
    private AuthenticationUserDetailService authenticationUserDetailService;

    public AuthenticationController(AuthenticationManager authenticationManager
    , AuthenticationUserDetailService authenticationUserDetailService) {
        this.authenticationManager = authenticationManager;
        this.authenticationUserDetailService = authenticationUserDetailService;
    }

    @PostMapping(value = "/authenticate")
    public String authenticated(@RequestBody UserAuthenRequest request) {
        // Request ที่เข้ามาเจอ Authentication Manager ที่เรามีอยู่ Verify ว่ามีในระบบหรือเปล่า
        // ไม่ต้องเขียน JPA หรือ JDBC ก็ได้เพราะมี Authentication Manager มาให้แล้ว มาเปรียบเทียบกัน

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.username(),
                request.password()
        ));
        // Authenticate Jwt from users

        // Return String jwt generate token
        return authenticationUserDetailService.generateJwt(request.username());

    }

}

record UserAuthenRequest(String username, String password) {}
