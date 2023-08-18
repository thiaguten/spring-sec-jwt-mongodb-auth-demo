package br.com.thiaguten.app.user.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
public class UserAuthManager 
    // Implementing UserDetailsService directly to keep things simple...
    implements UserDetailsService {
   // implements UserDetailsManager, UserDetailsPasswordService {

    private static final Logger log = LoggerFactory.getLogger(UserAuthManager.class);

    private final UserService userService;

    public UserAuthManager(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO cache?
        return userService.findByUsername(username)
                .orElseThrow(() -> {
                    log.error("Usuário auntenticação '{}'' não encontrado!", username);
                    return new UsernameNotFoundException(String.format("Usuário autenticação '%s' não encontrado", username));
                });
    }
    
}
