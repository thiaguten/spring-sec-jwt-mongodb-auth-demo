package br.com.thiaguten.app.utils;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
@Component
public class JwtHelper {

    public static final String STRING_SCOPE_DELIMITER = " ";
    public static final String AUTHORITY_PREFIX = "ROLE_";
    public static final String AUTHORITIES_CLAIM_NAME = "roles";

    // Default is 15 minutes (15 * 60 = 900 seconds)
    @Value("${security.jwt.expiry-in-seconds:900}")
    private long expiryInSeconds;

    private final JwtEncoder jwtEncoder;

    public JwtHelper(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public Jwt createJwt(UserDetails userDetails) {
        return createJwt(userDetails.getUsername(), userDetails.getAuthorities());
    }

    public Jwt createJwt(Authentication authentication) {
        return createJwt(authentication.getName(), authentication.getAuthorities());
    }

    public Jwt createJwt(String subject, Collection<? extends GrantedAuthority> authorities) {
        String scope = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(STRING_SCOPE_DELIMITER));
        // Sem timezone - (UTC)
        Instant now = Instant.now();
        long expiry = Duration.ofSeconds(expiryInSeconds).getSeconds();

        // https://datatracker.ietf.org/doc/html/rfc7519#section-4
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiry))
                .subject(subject)
                // .claim(AUTHORITIES_CLAIM_NAME, scope)
                .claim(AUTHORITIES_CLAIM_NAME, Arrays.asList(scope.split(STRING_SCOPE_DELIMITER)))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims));
    }

}
