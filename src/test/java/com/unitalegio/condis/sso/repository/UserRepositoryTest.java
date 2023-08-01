package com.unitalegio.condis.sso.repository;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.transaction.annotation.Transactional;

import javax.sql.DataSource;

@Deprecated
@Transactional
@DataJpaTest
class UserRepositoryTest {
    @Autowired
    private UserRepository userRepository;
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private DataSource dataSource;

    @Test
    void userSavedAndFetchedCorrectly() {
/*        String username = "supertestusername";
        UserEntity newUser = UserEntity.builder()
                .username("supertestusername")
                .credential("testcred")
                .email("testemail")
                .build();
        userRepository.save(newUser);

        entityManager.detach(newUser);
        newUser.setUsername("342434343434");

        Query q = entityManager.createQuery("select t from UserEntity t where t.username = :username");
        q.setParameter("username", username);
        UserEntity saved = (UserEntity) q.getResultList().get(0);

        Assertions.assertNotSame(newUser, saved);
        Assertions.assertNotEquals(newUser, saved);*/
    }
}