package br.com.thiaguten.app.user.service;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.thiaguten.app.user.model.User;
import br.com.thiaguten.app.user.model.UserRole;
import br.com.thiaguten.app.user.model.UserRole.AllowedRoles;
import br.com.thiaguten.app.user.repository.UserRepository;
import br.com.thiaguten.app.user.web.dto.NewUser;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public User save(NewUser newUser) {
        User user = User.of(
                newUser.getUsername(),
                encryptRawPassword(newUser.getPassword()),
                parseRoles(newUser.getAuthorities()));
        return userRepository.save(user);
    }

    public Set<UserRole> parseRoles(Set<String> rawAuthorities) {
        return rawAuthorities.stream()
                .map(AllowedRoles::valueOf)
                .map(UserRole::of)
                .collect(Collectors.toSet());
    }

    public String encryptRawPassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

}
