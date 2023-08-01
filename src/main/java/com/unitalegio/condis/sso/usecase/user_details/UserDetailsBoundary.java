package com.unitalegio.condis.sso.usecase.user_details;

/**
 * @author massenzio-p
 * @since 07.2023
 *
 * Interface for a boundary for User Details Use-case.
 */
interface UserDetailsBoundary {

    /**
     * Get user by the login.
     *
     * @param username - login;
     * @return - user object;
     */
    CondisUser getUserByLogin(String username);

}