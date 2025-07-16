package org.jwtsimple.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class TokenResponse {
    private String accessToken;
    private String tokenType = "Bearer";
    private long expiresIn;

    public TokenResponse(String accessToken, long expiresIn) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
    }
}
