package com.securityexample.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
@PreAuthorize("hasRole('USER') || hasRole('ADMIN')")
public class UserController {

    @GetMapping("/")
    public String allAccess() {
        return "Content for users";
    }
}
