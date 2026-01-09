package authservice.resource;

import authservice.dto.JwtResponse;
import authservice.dto.LoginRequest;
import authservice.entity.User;
import authservice.repository.UserRepository;
import authservice.service.JwtService;
import io.quarkus.elytron.security.common.BcryptUtil;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    UserRepository userRepository;

    @Inject
    JwtService jwtService;

    @POST
    @Path("/login")
    public Response login(LoginRequest request) {

        User user = userRepository.findByUsername(request.username())
                .filter(User::isEnabled)
                .orElse(null);

        if (user == null || !BcryptUtil.matches(request.password(), user.getPassword())) {
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }

        String token = jwtService.generateToken(user.getUsername(), user.getRole());

        return Response.ok(new JwtResponse(token)).build();
    }

}
