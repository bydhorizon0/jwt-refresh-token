package org.jwtsimple.repository;

import org.jwtsimple.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
     Optional<RefreshToken> findByToken(String token);
     void deleteByUserEmail(String email);
     void deleteByToken(String token);
}
