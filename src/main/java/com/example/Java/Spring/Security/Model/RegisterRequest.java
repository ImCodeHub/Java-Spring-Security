package com.example.Java.Spring.Security.Model;

import lombok.Data;

@Data
public class RegisterRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
