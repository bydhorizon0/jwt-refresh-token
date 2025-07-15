package org.jwtsimple.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class TokenResponse {
    private String accessToken;
    private long expiresIn;
}
