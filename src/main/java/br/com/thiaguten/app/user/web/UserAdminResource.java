package br.com.thiaguten.app.user.web;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.hateoas.MediaTypes;
import org.springframework.hateoas.mediatype.problem.Problem;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.thiaguten.app.user.model.User;
import br.com.thiaguten.app.user.service.UserService;
import br.com.thiaguten.app.user.web.dto.NewUser;
import br.com.thiaguten.app.user.web.dto.UserDTO;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
@RestController
@RequestMapping("/api/admin/v1/users")
public class UserAdminResource {

    private static final Logger log = LoggerFactory.getLogger(UserAdminResource.class);

    private final UserService userService;

    public UserAdminResource(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<?> create(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody @Valid NewUser newUser) {

        log.info("JWT Sub: {}", jwt.getSubject());
        log.info("Criando usuário novo: {}", newUser.getUsername());

        try {
            // Verifica se o usuário já existe.
            boolean exists = userService.findByUsername(newUser.getUsername()).isPresent();

            if (exists) {
                log.error("Usuário '{}' já cadastrado!", newUser.getUsername());
                return ResponseEntity
                        .status(HttpStatus.CONFLICT)
                        .header(HttpHeaders.CONTENT_TYPE, MediaTypes.HTTP_PROBLEM_DETAILS_JSON_VALUE)
                        .body(Problem.create()
                                .withTitle("Usuário já cadastrado!")
                                .withDetail("Não se pode salvar um novo usuário que já exista na base de dados"));
            }

            // Salva o novo usuário
            User user = userService.save(newUser);
            UserDTO userDTO = new UserDTO(user.getId().toString(), user.getUsername());
            return ResponseEntity.ok(userDTO);
        } catch (Exception e) {
            log.error("Falha inesperada ao criar um novo usuário", e);
            return ResponseEntity.internalServerError().build();
        }

    }

}
