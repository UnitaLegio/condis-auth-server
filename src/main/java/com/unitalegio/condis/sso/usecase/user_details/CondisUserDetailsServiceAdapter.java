package com.unitalegio.condis.sso.usecase.user_details;

import com.unitalegio.condis.sso.util.CollectionMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author massenzio-p
 * @since 07.2023
 *
 * Implementation for UserDetailsService to provide user data.
 */
@RequiredArgsConstructor
@Service
public class CondisUserDetailsServiceAdapter implements UserDetailsService {

    private final UserDetailsBoundary interactor;
    private final CollectionMapper<CondisUser, User> mapper = new UserDetailsMapper();

    /**
     * Finds User object in the storage by its name.
     *
     * @param username the username identifying the user whose data is required.
     * @return user details object;
     * @throws UsernameNotFoundException if user hasn't been found.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return mapper.mapTo(interactor.getUserByLogin(username));
    }
}
