
package com.zzy.security.rest.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/anonymity/api/v1")
public class AnonymityHelloController {

    @GetMapping(path = "/hello")
    public String anonymityHello() {
        return "anonymity hello";
    }
}
