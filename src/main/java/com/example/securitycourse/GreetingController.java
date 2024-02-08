package com.example.securitycourse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/greeting")
public class GreetingController {

    @RequestMapping(value="", method= RequestMethod.GET)
    public String greeting() {
        return "Hello, World";
    }
}
