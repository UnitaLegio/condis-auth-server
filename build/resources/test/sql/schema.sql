create schema if not exists condis_sso;

create table condis_sso.sso_users
(
    id          int generated always as identity
        primary key,
    username    varchar(255) unique                 not null,
    credentials varchar(1000)                       not null,
    email       varchar(255) unique                 not null,
    enabled     boolean   default true              null,
    confirmed   boolean   default false             not null,
    created_at  timestamp default CURRENT_TIMESTAMP null,
    updated_at  timestamp default CURRENT_TIMESTAMP null
);

create index condis_sso.user_idx_email
    on condis_sso.sso_users (email);

create index user_idx_username
    on condis_sso.sso_users (username);