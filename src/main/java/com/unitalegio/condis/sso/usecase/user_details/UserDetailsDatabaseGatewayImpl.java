package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.repository.UserEntity;
import com.unitalegio.condis.sso.util.CollectionMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * @author massenzio-p
 * @since 07.2023
 * <p>
 * Implementation of Database Gateway for User Details Use-case.
 */
@Component
@RequiredArgsConstructor
class UserDetailsDatabaseGatewayImpl implements UserDetailsDatabaseGateway {

    private final UserDetailsDAO dao;
    private final CollectionMapper<CondisUser, UserEntity> userEntityMapper = new UserEntityMapper();

    /**
     * Gets an entity of the user and maps it to domain model before return.
     *
     * @param username - login;
     * @return - domain user model.
     */
    @Override
    public CondisUser getUserByLogin(String username) {
        UserEntity entity = Optional.ofNullable(dao.getUserByLogin(username))
                .orElseThrow(() -> new UsernameNotFoundException(
                        String.format(
                                "User with name '%s' not found.",
                                username
                        )));
        return userEntityMapper.mapFrom(entity);
    }
}
