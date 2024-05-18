package net.unitalegio.condis.sso.repository;

import jakarta.persistence.*;
import lombok.*;

import java.sql.Timestamp;
import java.time.LocalDateTime;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
@EqualsAndHashCode
@Data
@Entity
@Table(name = "sso_users", schema = "condis_sso", catalog = "condis_sso")
public class UserEntity {
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    @Column(name = "id", insertable = false)
    private Long id;
    @Basic
    @Column(name = "username", nullable = false, unique = true)
    private String username;
    @Basic
    @Column(name = "credentials", nullable = false, length = 1000)
    private String credentials;
    @Basic
    @Column(name = "email", nullable = false, unique = true)
    private String email;
    @Basic
    @Column(name = "enabled")
    private Boolean enabled;
    @Basic
    @Column(name = "confirmed")
    private Boolean confirmed;
    @Basic
    @Column(name = "created_at", insertable = false)
    private LocalDateTime createdAt;
    @Basic
    @Column(name = "updated_at", insertable = false)
    private LocalDateTime updatedAt;
}
