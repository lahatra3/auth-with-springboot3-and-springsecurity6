package mg.lahatra3.springauth.auth;

import mg.lahatra3.springauth.auth.beans.AuthenticationRequest;
import mg.lahatra3.springauth.auth.beans.AuthenticationResponse;
import mg.lahatra3.springauth.auth.beans.RegisterRequest;
import mg.lahatra3.springauth.configuration.JwtService;
import mg.lahatra3.springauth.user.Role;
import mg.lahatra3.springauth.user.User;
import mg.lahatra3.springauth.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

   @Autowired
   private PasswordEncoder passwordEncoder;
   @Autowired
   private UserRepository userRepository;
   @Autowired
   private JwtService jwtService;
   @Autowired
   private AuthenticationManager authenticationManager;

   public AuthenticationResponse register(RegisterRequest request) {
      User user = User.builder()
             .firstname(request.getFirstname())
             .lastname(request.getLastname())
             .email(request.getEmail())
             .password(passwordEncoder.encode(request.getPassword()))
             .role(Role.USER).build();
      userRepository.save(user);
      String token = jwtService.generateToken(user);
      return AuthenticationResponse.builder()
             .token(token).build();
   }

   public AuthenticationResponse authenticate(AuthenticationRequest request) {
      authenticationManager.authenticate(
             new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
             )
      );
      User user = userRepository.findByEmail(request.getEmail()).orElseThrow();
      String token = jwtService.generateToken(user);
      return AuthenticationResponse.builder()
             .token(token).build();
   }
}
