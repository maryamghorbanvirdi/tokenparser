package tokenparser.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

@SpringBootApplication
/**
 * Utility class for Spring Security.
 */

public class TokenExtract {

  private final String realmRole;

  private final String attributeKey;

  public TokenExtract(String realmRole, String attributeKey) {
    this.realmRole = realmRole;
    this.attributeKey = attributeKey;
  }

  /**
   * Get the login of the current user.
   *
   * @return the login of the current user.
   */
  public Optional<String> getCurrentUserLogin() {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    return Optional.ofNullable(extractPrincipal(securityContext.getAuthentication()));
  }

  private String extractPrincipal(Authentication authentication) {
    if (authentication == null) {
      return null;
    } else if (authentication.getPrincipal() instanceof UserDetails) {
      UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
      return springSecurityUser.getUsername();
    } else if (authentication instanceof JwtAuthenticationToken) {
      return (String) ((JwtAuthenticationToken) authentication).getToken().getClaims().get("preferred_username");
    } else if (authentication.getPrincipal() instanceof DefaultOidcUser) {
      Map<String, Object> attributes = ((DefaultOidcUser) authentication.getPrincipal()).getAttributes();
      if (attributes.containsKey("preferred_username")) {
        return (String) attributes.get("preferred_username");
      }
    } else if (authentication.getPrincipal() instanceof String) {
      return (String) authentication.getPrincipal();
    }
    return null;
  }


  /**
   * Check if a user is authenticated.
   *
   * @return true if the user is authenticated, false otherwise.
   */
  //    public boolean isAuthenticated() {
  //        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
  //        return authentication != null &&
  //                getAuthorities(authentication).noneMatch(AuthoritiesConstants.ANONYMOUS::equals);
  //    }

  /**
   * If the current user has a specific authority (security role).
   * <p>
   * The name of this method comes from the {@code isUserInRole()} method in the Servlet API.
   *
   * @param authority the authority to check.
   * @return true if the current user has the authority, false otherwise.
   */
  public boolean isCurrentUserInRole(String authority) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication != null &&
        getAuthorities(authentication).anyMatch(authority::equals);
  }

  private Stream<String> getAuthorities(Authentication authentication) {
    Collection<? extends GrantedAuthority> authorities = authentication instanceof JwtAuthenticationToken ?
        extractAuthorityFromClaims(((JwtAuthenticationToken) authentication).getToken().getClaims())
        : authentication.getAuthorities();
    return authorities.stream()
        .map(GrantedAuthority::getAuthority);
  }

  public List<GrantedAuthority> extractAuthorityFromClaims(Map<String, Object> claims) {
    return mapRolesToGrantedAuthorities(getRolesFromClaims(claims));
  }

  @SuppressWarnings("unchecked")
  private Collection<String> getRolesFromClaims(Map<String, Object> claims) {
    return (Collection<String>) ((Map<String, Object>) claims.getOrDefault("resource_access",
        claims.getOrDefault("roles", new ArrayList<>()))).getOrDefault(this.realmRole, new ArrayList<>());
  }

  private List<GrantedAuthority> mapRolesToGrantedAuthorities(Collection<String> roles) {
    return roles.stream()
        .filter(role -> role.startsWith("ROLE_"))
        .map(SimpleGrantedAuthority::new)
        .collect(Collectors.toList());
  }

  public Optional<String> getUserId() {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    return Optional.ofNullable(securityContext.getAuthentication())
        .map(authentication -> authentication.getName());
  }

  public boolean hasAttribute(String attribute) {
    return getAttributes().stream().anyMatch(s -> s.equalsIgnoreCase(attribute));
  }


  public List<String> getAttributes() {
    String attributes= getToken().getClaim(attributeKey);
    return attributes!=null? List.of(((String) getToken().getClaim(attributeKey)).split(",")): new ArrayList<>();
  }

  public org.springframework.security.oauth2.jwt.Jwt getToken() {
    return ((org.springframework.security.oauth2.jwt.Jwt) SecurityContextHolder.getContext().getAuthentication().getCredentials());
  }
}
