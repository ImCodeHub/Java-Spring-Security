package com.example.Java.Spring.Security.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("admin/api")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    @GetMapping("greeting")
    public String greetingAdmin(){
        return "hello Interns how are you?";
    }
}
