package com.example.securitycourse.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class PublicController {

    @RequestMapping(value="", method= RequestMethod.GET)
    public String greeting() {
        return "Public Resource";
    }
}
