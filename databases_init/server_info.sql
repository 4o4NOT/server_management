-- auto-generated definition
create table server_info
(
    id                       bigint auto_increment
        primary key,
    host                     varchar(100) not null,
    port                     int          not null,
    username                 varchar(50)  not null,
    password                 varchar(255) not null,
    description              longtext     not null,
    last_password_change     datetime(6)  not null,
    current_duration         int          not null,
    generated_password       varchar(128) null,
    password_expiration_time datetime(6)  null
);

