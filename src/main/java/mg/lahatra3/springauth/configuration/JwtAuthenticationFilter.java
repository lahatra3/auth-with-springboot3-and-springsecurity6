package mg.lahatra3.springauth.configuration;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

   @Autowired
   private JwtService jwtService;
   @Autowired
   private UserDetailsService userDetailsService;


   @Override
   protected void doFilterInternal(
          @NonNull HttpServletRequest request,
          @NonNull HttpServletResponse response,
          @NonNull FilterChain filterChain
   ) throws ServletException, IOException {
      String authHeader = request.getHeader("Authorization");
      if (Objects.isNull(authHeader) || !authHeader.startsWith("Bearer ")) {
         filterChain.doFilter(request, response);
         return;
      }

      final String token = authHeader.substring(7);
      final String userEmail = jwtService.extractUsername(token);

      if (Objects.nonNull(userEmail) && Objects.isNull(SecurityContextHolder.getContext().getAuthentication())) {
         UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
         if (jwtService.isTokenValid(token, userDetails)) {
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                   userDetails,
                   null,
                   userDetails.getAuthorities()
            );

            authToken.setDetails(
                   new WebAuthenticationDetailsSource().buildDetails(request)
            );
            SecurityContextHolder.getContext().setAuthentication(authToken);
         }
      }
      filterChain.doFilter(request, response);
   }
}
