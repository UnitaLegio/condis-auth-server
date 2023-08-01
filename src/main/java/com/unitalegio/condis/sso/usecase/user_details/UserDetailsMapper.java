package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.util.CollectionMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @author massenzio-p
 * @since 07.2023
 *
 * Mapper for UserDetails default implementation.
 */
public class UserDetailsMapper implements CollectionMapper<CondisUser, User> {
    /**
     * Converts from domain model to spring user details default implementation.
     *
     * @param condisUser - domain model object;
     * @return user details.
     */
    @Override
    public User mapTo(CondisUser condisUser) {
        return new User(
                condisUser.getUsername(),
                condisUser.getCredentials(),
                condisUser.getEnabled(),
                condisUser.getAccountNonExpired(),
                condisUser.getCredentialsNonExpired(),
                condisUser.getAccountNonLocked(),
                List.of()
        );
    }

    /**
     * Converts default user details object to domain model.
     *
     * @param userDetails - user details object;
     * @return condis user domain model.
     */
    @Override
    public CondisUser mapFrom(User userDetails) {
        return CondisUser.builder()
                .username(userDetails.getUsername())
                .credentials(userDetails.getPassword())
                .enabled(userDetails.isEnabled())
                .accountNonExpired(userDetails.isAccountNonExpired())
                .credentialsNonExpired(userDetails.isCredentialsNonExpired())
                .accountNonLocked(userDetails.isAccountNonLocked())
                .build();
    }
}
