package com.example.securitycourse.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {
    @RequestMapping(value="", method= RequestMethod.GET)
    public String greeting() {
        return "Admin resource";
    }
}
