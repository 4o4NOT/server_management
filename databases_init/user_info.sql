-- auto-generated definition
create table user_info
(
    id           bigint auto_increment
        primary key,
    user_name    varchar(20)  not null,
    phone        varchar(11)  not null,
    password     varchar(128) not null,
    is_superuser tinyint(1)   not null,
    is_active    tinyint(1)   not null,
    last_login   datetime(6)  null,
    date_joined  datetime(6)  not null,
    otp_secret   varchar(32)  null,
    otp_active   tinyint(1)   not null,
    constraint phone
        unique (phone),
    constraint user_name
        unique (user_name)
);

