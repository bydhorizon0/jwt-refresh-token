package org.jwtsimple.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.jwtsimple.entity.RefreshToken;
import org.jwtsimple.repository.RefreshTokenRepository;
import org.jwtsimple.util.JwtUtil;
import org.springframework.stereotype.Service;

import java.util.Date;

@Log4j2
@RequiredArgsConstructor
@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    @Transactional
    public RefreshToken createRefreshToken(String email) {
        refreshTokenRepository.deleteByUserEmail(email);

        String refreshToken = jwtUtil.generateRefreshToken(email);

        RefreshToken refreshTokenEntity = new RefreshToken(refreshToken, email, new Date(System.currentTimeMillis() + JwtUtil.REFRESH_EXPIRATION_TIME));

        return refreshTokenRepository.save(refreshTokenEntity);
    }

}
