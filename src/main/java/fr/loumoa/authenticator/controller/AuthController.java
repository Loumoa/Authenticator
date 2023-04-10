package fr.loumoa.authenticator.controller;

import fr.loumoa.authenticator.model.Role;
import fr.loumoa.authenticator.model.User;
import fr.loumoa.authenticator.payload.request.LoginRequest;
import fr.loumoa.authenticator.payload.request.RolesRequest;
import fr.loumoa.authenticator.payload.request.SignupRequest;
import fr.loumoa.authenticator.payload.response.JwtResponse;
import fr.loumoa.authenticator.payload.response.MessageResponse;
import fr.loumoa.authenticator.payload.response.TokenResponse;
import fr.loumoa.authenticator.repository.RoleRepository;
import fr.loumoa.authenticator.repository.UserRepository;
import fr.loumoa.authenticator.security.jwt.JwtUtils;
import fr.loumoa.authenticator.security.services.UserDetailsImpl;
import fr.loumoa.authenticator.util.RoleUtil;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;


    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping(value = "/signin", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping(value = "/signup", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<Role> roles = RoleUtil.adaptRoles(signUpRequest.getRole(), roleRepository);

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @GetMapping(value = "/get-public-key")
    public ResponseEntity<?> getPublicKeys(){
        return ResponseEntity.ok(new TokenResponse(
                Base64.getEncoder().encodeToString(jwtUtils.getPublicKey().getEncoded())
        ));
    }

    @PutMapping(value = "/{userId}/roles")
    public ResponseEntity<?> updateRoles(@PathVariable("userId") String userId,
                                         @Valid @RequestBody RolesRequest rolesStr){
        if (! userRepository.existsById(Long.parseLong(userId))){
            return  ResponseEntity.badRequest().body("Error : id not found");
        }

        Set<Role> roles = RoleUtil.adaptRoles(rolesStr.getRole(), roleRepository);
        User user = userRepository.findById(Long.parseLong(userId))
                .orElseThrow();
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok("");
    }
}
