drop schema if exists condis_sso;
create schema condis_sso;
SET SCHEMA condis_sso;

create table sso_user
(
    id          int auto_increment
        primary key,
    username    varchar(255)                        not null comment 'Login',
    credentials varchar(1000)                       not null comment 'Hashed credentials',
    email       varchar(255)                        not null comment 'User''s email',
    enabled     tinyint   default 1                 null comment 'Whether user is enabled',
    created_at  timestamp default CURRENT_TIMESTAMP null comment 'When user was created',
    updated_at  timestamp default CURRENT_TIMESTAMP null comment 'Last time of user''s update',
    constraint email
        unique (email),
    constraint username
        unique (username)
);
comment on table sso_user is 'Condis Users';

create index user_idx_email
    on sso_user (email);

create index user_idx_username
    on sso_user (username);