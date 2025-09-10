create table server_management.permission_application
(
    id           bigint auto_increment
        primary key,
    account_name varchar(50) not null,
    reason       longtext    not null,
    duration     int         not null,
    status       varchar(20) not null,
    applied_at   datetime(6) not null,
    approved_at  datetime(6) null,
    expired_at   datetime(6) null,
    applicant_id bigint      not null,
    server_id    bigint      not null,
    constraint permission_application_applicant_id_6d3c61e2_fk_user_info_id
        foreign key (applicant_id) references server_management.user_info (id),
    constraint permission_application_server_id_5e462a94_fk_server_info_id
        foreign key (server_id) references server_management.server_info (id)
);

