package org.spring.jwt.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.spring.jwt.dto.AuthUser;
import org.spring.jwt.dto.RegUser;
import org.spring.jwt.entity.Role;
import org.spring.jwt.entity.User;
import org.spring.jwt.mapper.RegUserMapper;
import org.spring.jwt.repository.RoleRepository;
import org.spring.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;


@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {
    @Value("${failed.attempts}")
    private int MAX_FAILED_ATTEMPTS;

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;

    public User register(RegUser regUser) {
        Set<Role> userRoles = regUser.getRoles().stream()
                .map(roleName -> roleRepository.findByName(roleName)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found: " + roleName)))
                .collect(Collectors.toSet());
        User user = RegUserMapper.mapToUser(regUser, passwordEncoder, userRoles);
        return userRepository.save(user);
    }

    public void unlockAccount(String username) {
        userRepository.unlockUserAccount(username);
    }


    public User auth(AuthUser authUser) {
        User user = userRepository.findByUsername(authUser.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException(authUser.getUsername()));
        if(!user.isAccountNonLocked()) {
            throw new AccessDeniedException("Access denied");
        }
        boolean matches = passwordEncoder.matches(authUser.getPassword(), user.getPassword());
        if(!matches) {
            if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                userRepository.lockUserAccount(user.getUsername());
                log.info("Account " + user.getUsername() + " is locked");
            } else {
                int count = user.getFailedAttempts() + 1;
                userRepository.incrementFailedLoginAttempts(user.getUsername(), count);
                log.info("Failed login attempt");
            }
        }

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authUser.getUsername(), authUser.getPassword()));
        log.info("Login success");
        return user;
    }

    public User findByUsername(String username) {
        User result = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return result;
    }
}
