package br.com.thiaguten.app.user.web.dto;

import java.time.Instant;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
public class UserAuthDTO {

    private String username;
    private String token;
    private Instant expiresAt;
    private long expiresAtEpochSecond;

    public UserAuthDTO() {
        super();
    }

    public UserAuthDTO(String username, String token, Instant expiresAt) {
        this.username = username;
        this.token = token;
        this.expiresAt = expiresAt;
        this.expiresAtEpochSecond = expiresAt.getEpochSecond();
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public long getExpiresAtEpochSecond() {
        return expiresAtEpochSecond;
    }

    public void setExpiresAtEpochSecond(long expiresAtEpochSecond) {
        this.expiresAtEpochSecond = expiresAtEpochSecond;
    }

}
