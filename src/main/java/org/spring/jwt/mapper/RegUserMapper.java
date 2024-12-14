package org.spring.jwt.mapper;

import org.spring.jwt.dto.RegUser;
import org.spring.jwt.entity.Role;
import org.spring.jwt.entity.User;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

public class RegUserMapper {
    public static User mapToUser(RegUser regUser, PasswordEncoder passwordEncoder, Set<Role> userRoles) {

        return User.builder()
                .username(regUser.getUsername())
                .password(passwordEncoder.encode(regUser.getPassword()))
                .roles(userRoles)
                .isAccountNonLocked(true)
                .build();
    }
}
