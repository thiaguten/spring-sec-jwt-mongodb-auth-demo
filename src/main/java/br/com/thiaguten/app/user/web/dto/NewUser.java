package br.com.thiaguten.app.user.web.dto;

import java.util.HashSet;
import java.util.Set;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
public class NewUser {

    @NotBlank
    private String username;

    @NotBlank
    private String password;

    @NotEmpty
    private Set<String> authorities = new HashSet<>();

    public NewUser() {
        super();
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(Set<String> authorities) {
        this.authorities = authorities;
    }

}
