package org.jwtsimple.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.jwtsimple.entity.RefreshToken;
import org.jwtsimple.entity.User;
import org.jwtsimple.model.LoginRequest;
import org.jwtsimple.model.RegisterRequest;
import org.jwtsimple.model.TokenResponse;
import org.jwtsimple.service.RefreshTokenService;
import org.jwtsimple.service.UserService;
import org.jwtsimple.util.JwtUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@Log4j2
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@RestController
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final RefreshTokenService refreshTokenService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            User user = userService.findByEmail(loginRequest.getEmail());

            String accessToken = jwtUtil.generateAccessToken(user.getEmail());
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

            ResponseCookie cookie = ResponseCookie.from("my-cookie", refreshToken.getToken())
                    .httpOnly(true)
                    .secure(true)
                    // .domain("localhost")
                    .path("/api/auth")
                    .maxAge(JwtUtil.calcExpiresIn(JwtUtil.ACCESS_EXPIRATION_TIME))
                    .build();

            TokenResponse tokenResponse = new TokenResponse(accessToken, JwtUtil.calcExpiresIn(JwtUtil.ACCESS_EXPIRATION_TIME));

            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(tokenResponse);
        } catch (BadCredentialsException e) {
            log.error(e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid credentials");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        if (userService.findByEmail(request.getEmail()) != null) {
            return ResponseEntity.badRequest()
                    .body("이미 존재하는 이메일입니다.");
        }

        User user = new User(request.getEmail(), request.getPassword());

        userService.saveUser(user);

        return ResponseEntity.ok("Register successfully");
    }
}
