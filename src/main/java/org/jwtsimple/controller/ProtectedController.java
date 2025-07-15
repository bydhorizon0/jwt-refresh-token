package org.jwtsimple.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/api")
@RestController
public class ProtectedController {

    @GetMapping("/user/profile")
    public ResponseEntity<?> userProfile(Authentication authentication) {
        String email = authentication.getName();
        GrantedAuthority authority = authentication.getAuthorities()
                .stream()
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("Username not found"));

        String role = authority.getAuthority();
        System.out.println(role);

        return ResponseEntity.ok().body(email);
    }
}
