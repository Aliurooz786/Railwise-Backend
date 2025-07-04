package com.example.demo.controller;


import com.example.demo.entity.User;
import com.example.demo.services.UserService;
import com.example.demo.services.serviceImpl.UserDetailsServiceImpl;
import com.example.demo.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;


@Slf4j
@RestController
@RequestMapping("/users")
public class UserController{

    @Autowired
    private UserService userService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private PasswordEncoder passwordEncoder;


    @GetMapping("/all")
    public ResponseEntity<List<User>> findAllUsers() {
        log.info("Received request to fetch all users");
        List<User> users = userService.getAllUsers();
        log.info("Fetched {} users from database", users.size());
        return ResponseEntity.ok(users);
    }

    @PutMapping("/update/{id}")
    public ResponseEntity<?> updateUser(@PathVariable String id, @RequestBody User updatedUser) {
        log.info("Update request received for user ID: {}", id);
        User user = userService.updateUser(id, updatedUser);
        if (user == null) {
            log.warn("User not found with ID: {}", id);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
        log.info("User updated successfully for ID: {}", id);
        return ResponseEntity.ok(user);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable String id) {
        log.info("Delete request for user ID: {}", id);
        boolean deleted = userService.deleteUser(id);
        if (deleted) {
            log.info("User deleted with ID: {}", id);
            return ResponseEntity.ok("User deleted successfully.");
        } else {
            log.warn("User not found with ID: {}", id);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found.");
        }
    }

    @GetMapping("/email")
    public ResponseEntity<?> getUserByEmail(@RequestParam String email) {
        log.info("Fetch user by email: {}", email);
        Optional<User> user = userService.getUserByEmailId(email);
        if (user.isPresent()) {
            log.info("User found with email: {}", email);
            return ResponseEntity.ok(user.get());
        } else {
            log.warn("User not found with email: {}", email);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found with email: " + email);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        log.info("Registering user: {}", user.getEmail());
        String result = userService.registerUser(user);
        log.info("Registration result: {}", result);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/admin/register")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> registerAdmin(@RequestBody User user) {
        log.info("Admin registration requested by: {}", user.getEmail());
        String result = userService.registerAdmin(user);
        log.info("Admin registration result: {}", result);
        return ResponseEntity.ok(result);
    }



    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody Map<String, String> loginData) {
        String email = loginData.get("email");
        String password = loginData.get("password");
        log.info("Login attempt for email: {}", email);
        Optional<User> userOpt = userService.getUserByEmailId(email);
        if (userOpt.isEmpty()) {
            log.warn("Email not found: {}", email);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Email not found");
        }

        String encodedPassword = userOpt.get().getPassWord();

        if (!passwordEncoder.matches(password, encodedPassword)) {
            log.warn("Incorrect password for email: {}", email);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Password incorrect");
        }
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);
        String token = jwtUtil.generateToken(userDetails);
        log.info("Login successful for email: {}", email);
        return ResponseEntity.ok(Map.of("token", token));
    }

    @GetMapping("/test")
    public ResponseEntity<String> testJWTAccess() {
        log.info("Protected test endpoint accessed successfully.");
        return ResponseEntity.ok("Accessed protected endpoint with valid JWT!");
    }
}