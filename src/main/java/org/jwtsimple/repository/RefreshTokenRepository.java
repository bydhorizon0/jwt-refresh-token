package org.jwtsimple.repository;

import org.jwtsimple.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
     void deleteByUserEmail(String email);
}
