package org.jwtsimple.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
@Entity
@Table(name = "users")
public class User extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String email;

    private String password;

    private String role;

    public User(String email, String password) {
        this.email = email;
        this.password = password;
        this.role = "USER";
    }

    public void setEncryptPassword(String encryptPassword) {
        this.password = encryptPassword;
    }
}
