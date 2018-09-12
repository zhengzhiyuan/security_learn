
package com.zzy.security.rest.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/v1")
public class AdminHelloController {

    @GetMapping(path = "/hello")
    public String hello() {
        return "admin hello";
    }

}
