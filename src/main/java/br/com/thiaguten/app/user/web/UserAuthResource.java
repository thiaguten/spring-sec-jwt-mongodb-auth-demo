package br.com.thiaguten.app.user.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import br.com.thiaguten.app.user.service.UserService;
import br.com.thiaguten.app.user.web.dto.UserAuthDTO;
import br.com.thiaguten.app.utils.JwtHelper;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
@RestController
@RequestMapping("/api/public/v1/users")
public class UserAuthResource {

    private static final Logger log = LoggerFactory.getLogger(UserAuthResource.class);

    private final JwtHelper jwtHelper;
    private final UserService userService;

    public UserAuthResource(JwtHelper jwtHelper, UserService userService) {
        this.jwtHelper = jwtHelper;
        this.userService = userService;
    }

    @GetMapping(value = "/passwordEncoder", produces = MediaType.TEXT_PLAIN_VALUE)
    public String passwordEncoder(@RequestParam(name = "rawPassword", required = true) String rawPassword) {
        return userService.encryptRawPassword(rawPassword);
    }

    @PostMapping("/login")
    public ResponseEntity<UserAuthDTO> login(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION) String basicAuthHeader,
            Authentication authentication) {
        try {
            // https://en.wikipedia.org/wiki/Basic_access_authentication
            log.info("Authentication Name: {}", authentication.getName());

            // Cria um jwt para o usuário autenticado.
            Jwt jwt = jwtHelper.createJwt(authentication);
            // Jwt jwt = jwtHelper.createJwt((org.springframework.security.core.userdetails.UserDetails) authentication.getPrincipal());
            // Jwt jwt = jwtHelper.createJwt((org.springframework.security.core.userdetails.User) authentication.getPrincipal());
            String token = jwt.getTokenValue();

            // Cria o dto para o reponse body.
            UserAuthDTO userAuthDTO = new UserAuthDTO(jwt.getSubject(), token, jwt.getExpiresAt());

            // Retorna a resposta com o token no cabeçalho.
            return ResponseEntity.ok()
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .body(userAuthDTO);

        } catch (BadCredentialsException bcex) {
            log.error("Falha na validação do esquema de autenticação HTTP 'Basic' - usuário desconhecido.", bcex);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception ex) {
            log.error("Falha inesperada durante processo de login e geração de token (JWT)", ex);
            return ResponseEntity.internalServerError().build();
        }
    }

    
}
