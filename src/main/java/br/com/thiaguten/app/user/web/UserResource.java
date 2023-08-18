package br.com.thiaguten.app.user.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
public class UserResource {

    @GetMapping("/greeting")
    public String greeting(@AuthenticationPrincipal Jwt jwt) {
        return "Olá, " + jwt.getSubject();
    }

}
