package br.com.thiaguten.app.user.repository;

import java.util.Optional;

import org.bson.types.ObjectId;
import org.springframework.data.mongodb.repository.MongoRepository;

import br.com.thiaguten.app.user.model.User;

/**
 * 
 * @author Thiago Gutenberg Carvalho da Costa
 */
public interface UserRepository extends MongoRepository<User, ObjectId> {

    Optional<User> findByUsername(String username);
    
}
