package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.repository.UserEntity;
import com.unitalegio.condis.sso.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * @author massenzio-p
 * @since 07.2023
 *
 * A DAO for User Details Use-case.
 */
@Component
@RequiredArgsConstructor
public class UserDetailsDAO {

    private final UserRepository userRepository;

    /**
     * Get user by the login.
     *
     * @param username - login;
     * @return user entity.
     */
    UserEntity getUserByLogin(String username) {
        return userRepository.findByUsername(username);
    }
}
