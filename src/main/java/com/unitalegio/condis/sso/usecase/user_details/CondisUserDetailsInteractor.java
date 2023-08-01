package com.unitalegio.condis.sso.usecase.user_details;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * @author massenzio-p
 * @since 07.2023
 *
 * An interactor implementation for User Details Use-case.
 */
@RequiredArgsConstructor
@Component
class CondisUserDetailsInteractor implements UserDetailsBoundary {

    private final UserDetailsDatabaseGateway databaseGateway;

    /**
     * Get user by the login.
     *
     * @param username - login;
     * @return - user object;
     */
    @Override
    public CondisUser getUserByLogin(String username) {
        return databaseGateway.getUserByLogin(username);
    }
}
