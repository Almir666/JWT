package org.spring.jwt.repository;

import jakarta.transaction.Transactional;
import org.spring.jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.isAccountNonLocked = false WHERE u.username = :username")
    void lockUserAccount(@Param("username") String username);

    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.isAccountNonLocked = true, u.failedAttempts = 0 WHERE u.username = :username")
    void unlockUserAccount(@Param("username") String username);

    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = :count WHERE u.username = :username")
    void incrementFailedLoginAttempts(@Param("username") String username,@Param("count") int count);
}
