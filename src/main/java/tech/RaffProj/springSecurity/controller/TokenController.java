package tech.RaffProj.springSecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import tech.RaffProj.springSecurity.controller.dto.LoginRequest;
import tech.RaffProj.springSecurity.controller.dto.LoginResponse;
import tech.RaffProj.springSecurity.entities.Role;
import tech.RaffProj.springSecurity.repository.UserRepository;

import java.time.Instant;
import java.util.stream.Collectors;

@RestController

public class TokenController {
    private final JwtEncoder jwtEncoder;
    //injetando userRepository para pegar info de usuario e senha e validar correspondencia
    private final UserRepository userRepository;
    //Injetando bean bcrypt para validar senha digitada
    private BCryptPasswordEncoder passwordEncoder;

    public TokenController(JwtEncoder jwtEncoder, UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;

    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse>login(@RequestBody LoginRequest loginRequest) {
        var user = userRepository.findByUsername(loginRequest.username());

        if (user.isEmpty() || !user.get().isLoginCorret(loginRequest, passwordEncoder)) {
            throw new BadCredentialsException("User or password is invalid");
        }

        var now = Instant.now();
        var expiresIn = 300L;

        var scopes = user.get().getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.joining(" "));

        var claims = JwtClaimsSet.builder()
                .issuer("mybackend")
                .subject(user.get().getUserId().toString())
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiresIn))
                .claim("scope", scopes)
                .build();

        var jwtValue = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();

        return ResponseEntity.ok(new LoginResponse(jwtValue, expiresIn));
    }

}
