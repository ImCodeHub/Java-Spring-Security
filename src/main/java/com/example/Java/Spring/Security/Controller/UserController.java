package com.example.Java.Spring.Security.Controller;

import com.example.Java.Spring.Security.Model.AuthenticationRequest;
import com.example.Java.Spring.Security.Model.AuthenticationResponse;
import com.example.Java.Spring.Security.Model.RegisterRequest;
import com.example.Java.Spring.Security.Service.UserService.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/auth")
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("user-register")
    public ResponseEntity<AuthenticationResponse> userRegister(@RequestBody RegisterRequest registerRequest){
        AuthenticationResponse authenticationResponse = userService.saveUser(registerRequest);
        return new ResponseEntity<>(authenticationResponse, HttpStatus.CREATED);
    }

    @PostMapping("login")
        public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request){
        AuthenticationResponse authenticate = userService.authenticate(request);
        return new ResponseEntity<>(authenticate, HttpStatus.FOUND);
        }

}
