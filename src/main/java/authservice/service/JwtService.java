package authservice.service;

import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Duration;
import java.util.Set;

@ApplicationScoped
public class JwtService {

    public String generateToken(String username, String role) {
        return Jwt.issuer("https://miempresa.com/issuer")
                .upn(username)
                .groups(Set.of(role))
                .expiresIn(Duration.ofMinutes(1))
                .sign();
    }

}
