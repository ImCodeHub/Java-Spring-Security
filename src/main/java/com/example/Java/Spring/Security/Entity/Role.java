package com.example.Java.Spring.Security.Entity;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

public enum Role {
    ADMIN,
    USER,
    HR,
    MANAGER;

    public List<SimpleGrantedAuthority> getAuthorities(){
        return List.of(new SimpleGrantedAuthority("ROLE_"+this.name())); //ROLE_USER, ROLE_ADMIN, ROLE_HR, ROLE_MANAGER
    }
}
