package br.com.thiaguten.app.user.web.dto;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
public class UserDTO {

    private String id;
    private String username;

    public UserDTO() {
        super();
    }

    public UserDTO(String id, String username) {
        this.id = id;
        this.username = username;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

}
