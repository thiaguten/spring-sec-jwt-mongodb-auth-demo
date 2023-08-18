package br.com.thiaguten.app.user.model;

import java.util.Objects;

import org.springframework.data.mongodb.core.mapping.Field;
import org.springframework.security.core.GrantedAuthority;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
public class UserRole implements GrantedAuthority {

    public enum AllowedRoles {
        USER("Usuário externo - cliente"),
        ADMIN("Usuário interno - administrativo");

        private final String name;
        private final String description;

        AllowedRoles(String description) {
            this.name = this.name();
            this.description = description;
        }

        public String getName() {
            return name;
        }

        public String getDescription() {
            return description;
        }
    }

    @Field("name")
    private String authority;
    private String description;

    public UserRole() {
        super();
    }

    // factory method
    public static UserRole of(String authority) {
        return UserRole.of(AllowedRoles.valueOf(authority));
    }

    // factory method
    public static UserRole of(AllowedRoles authority) {
        Objects.requireNonNull(authority, "AllowedRoles must not be null");
        UserRole userAuthRole = new UserRole();
        userAuthRole.setAuthority(authority.getName());
        userAuthRole.setDescription(authority.getDescription());
        return userAuthRole;
    }

    @Override
    public String getAuthority() {
        return authority;
    }

    public void setAuthority(String authority) {
        this.authority = authority;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public int hashCode() {
        return Objects.hash(authority);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof UserRole))
            return false;
        UserRole other = (UserRole) obj;
        return Objects.equals(authority, other.authority);
    }

}
