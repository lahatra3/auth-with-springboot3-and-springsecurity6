package mg.lahatra3.springauth.configuration;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Service
public class JwtService {

   @Value("${security.jwt.secret-key}")
   private String JWT_SECRET_KEY;
   @Value("${security.jwt.expiration.access-token}")
   private String JWT_EXPIRATION_ACCESS_TOKEN;


   public String extractUsername(String token) {
      return extractClaim(token, Claims::getSubject);
   }

   public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
      final Claims claims = extractionAllClaims(token);
      return claimsResolver.apply(claims);
   }

   public String generateToken(UserDetails userDetails) {
      return generateToken(new HashMap<>(), userDetails);
   }

   public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
      Map<String,Object> header = new HashMap<>();
      header.put("typ","JWT");

      return Jwts
             .builder()
             .setHeader(header)
             .setClaims(extraClaims)
             .setSubject(userDetails.getUsername())
             .setIssuedAt(
                    new Date(
                           System.currentTimeMillis()
                    )
             )
             .setExpiration(
                    new Date(
                           System.currentTimeMillis() + Integer.parseInt(JWT_EXPIRATION_ACCESS_TOKEN)
                    )
             )
             .signWith(getSignInKey(), SignatureAlgorithm.HS512)
             .compact();
   }

   public boolean isTokenValid(String token, UserDetails userDetails) {
      final String username = extractUsername(token);
      return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
   }

   private boolean isTokenExpired(String token) {
      return extractExpiration(token).before(new Date());
   }

   private Date extractExpiration(String token) {
      return extractClaim(token, Claims::getExpiration);
   }

   private Claims extractionAllClaims(String token) {
      return Jwts.parserBuilder()
             .setSigningKey(getSignInKey())
             .build()
             .parseClaimsJws(token)
             .getBody();
   }

   private Key getSignInKey() {
      return Keys.hmacShaKeyFor(JWT_SECRET_KEY.getBytes());
   }
}
