package com.unitalegio.condis.sso.usecase.user_details;

/**
 * @author massenzio-p
 * @since 07.2023
 *
 * Interface for a gateway to database.
 */
interface UserDetailsDatabaseGateway {

    /**
     * Gets an entity of the user and maps it to domain model before return.
     *
     * @param username - login;
     * @return - domain user model.
     */
    CondisUser getUserByLogin(String username);
}
