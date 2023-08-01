package com.unitalegio.condis.sso.usecase.user_details;

import lombok.*;

import java.time.LocalDateTime;

/**
 * @author massenzio-p
 * @since 07.2023
 *
 * Condis User Domain Model.
 */
@ToString
@EqualsAndHashCode
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
class CondisUser implements Cloneable {
    private Long userId;
    private String username;
    private String credentials;
    private String email;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Boolean enabled;
    private Boolean accountNonExpired;
    private Boolean credentialsNonExpired;
    private Boolean accountNonLocked;

    @Override
    public CondisUser clone() {
        try {
            return (CondisUser) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError();
        }
    }
}
