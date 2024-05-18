package net.unitalegio.condis.sso.repository;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

/**
 * @author massenzio-p
 * @since 07.2023
 *
 * Repository for user table.
 */
@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long> {

    /**
     * Find user by the login.
     *
     * @param username - user's login;
     * @return User Entity.
     */
    UserEntity findByUsername(String username);
}
