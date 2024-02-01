package mg.lahatra3.springauth.auth;

import lombok.RequiredArgsConstructor;
import mg.lahatra3.springauth.auth.beans.AuthenticationRequest;
import mg.lahatra3.springauth.auth.beans.AuthenticationResponse;
import mg.lahatra3.springauth.auth.beans.RegisterRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

   @Autowired
   private AuthenticationService authenticationService;


   @PostMapping("/register")
   public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
      return  ResponseEntity.status(HttpStatus.CREATED)
             .body(authenticationService.register(request));
   }

   @PostMapping("authenticate")
   public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
      return ResponseEntity.ok(authenticationService.authenticate(request));
   }
}
