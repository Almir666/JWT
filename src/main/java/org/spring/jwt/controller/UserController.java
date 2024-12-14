package org.spring.jwt.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.spring.jwt.dto.AuthUser;
import org.spring.jwt.dto.RegUser;
import org.spring.jwt.dto.UnlockUser;
import org.spring.jwt.entity.User;
import org.spring.jwt.security.jwt.JwtUtils;
import org.spring.jwt.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final JwtUtils jwtUtils;

    @PostMapping("/registration")
    public ResponseEntity<String> register(@RequestBody RegUser regUser) {
        userService.register(regUser);
        log.info("User " + regUser.getUsername() + " registered");
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }

    @PostMapping("/authenticate")
    public ResponseEntity<String> auth(@RequestBody AuthUser authUser) {
        User auth = userService.auth(authUser);
        return ResponseEntity.ok(jwtUtils.generateJwt(auth));
    }

    @GetMapping("/user")
    public String testMethod() {
        return "General information for all";
    }

    @GetMapping("/moderate")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderate() {
        return "Data for moderators";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String admin() {
        return "Data for Super Admin";
    }

    @PostMapping("/admin/unlock")
    public ResponseEntity<String> unlockUserAccount(@RequestBody UnlockUser user) {
        userService.unlockAccount(user.getUsername());
        return ResponseEntity.ok("User " + user.getUsername() + " is unlocked");
    }
}
