package com.example.Java.Spring.Security.Service.UserService;

import com.example.Java.Spring.Security.Entity.User;
import com.example.Java.Spring.Security.Model.AuthenticationRequest;
import com.example.Java.Spring.Security.Model.AuthenticationResponse;
import com.example.Java.Spring.Security.Model.RegisterRequest;
import com.example.Java.Spring.Security.Repository.UserRepository;
import com.example.Java.Spring.Security.Service.JwtService.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    //method for user Registration
    public AuthenticationResponse saveUser(RegisterRequest registerRequest){
        User user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(registerRequest.getPassword())
                .role(registerRequest.getRole()).build();

        User savedUser = userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder().accessToken(jwtToken).build();
    }

}
