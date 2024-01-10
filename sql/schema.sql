CREATE TABLE tenants (
    id       SERIAL                             ,
    created  TIMESTAMP    NOT NULL              ,
    deleted  TIMESTAMP                          ,
    active   BOOLEAN      NOT NULL DEFAULT true ,
    code     VARCHAR(64)  NOT NULL              ,
    name     VARCHAR(128) NOT NULL              ,
    UNIQUE      (code)                          ,
    UNIQUE      (name)                          ,
    PRIMARY KEY (id)
);

CREATE TABLE accounts (
    id       SERIAL                                         ,
    created  TIMESTAMP    NOT NULL                          ,
    deleted  TIMESTAMP                                      ,
    tenant   BIGINT       NOT NULL REFERENCES tenants (id)  ,
    active   BOOLEAN      NOT NULL DEFAULT true             ,
    code     VARCHAR(16)  NOT NULL                          ,
    name     VARCHAR(64)  NOT NULL                          ,
    UNIQUE      (tenant, name)                              ,
    UNIQUE      (code)                                      ,
    PRIMARY KEY (id)
);

CREATE TABLE users (
    id       SERIAL                                         ,
    created  TIMESTAMP    NOT NULL                          ,
    deleted  TIMESTAMP                                      ,
    account  BIGINT       NOT NULL REFERENCES accounts (id) ,
    kind     CHAR(2)                                        ,
    active   BOOLEAN      NOT NULL DEFAULT true             ,
    code     VARCHAR(128) NOT NULL                          ,
    email    VARCHAR(256) NOT NULL                          ,
    UNIQUE      (code)                                      ,
    UNIQUE      (account, email)                            ,
    PRIMARY KEY (id)
);

CREATE TABLE pins (
    id       SERIAL                                         ,
    created  TIMESTAMP    NOT NULL                          ,
    deleted  TIMESTAMP                                      ,
    user_id  BIGINT       NOT NULL REFERENCES users (id)    ,
    pin      VARCHAR(128) NOT NULL                          ,
    PRIMARY KEY (id)
);

CREATE TABLE applications (
    id       SERIAL                               ,
    created  TIMESTAMP    NOT NULL                ,
    deleted  TIMESTAMP                            ,
    active   BOOLEAN      NOT NULL DEFAULT true   ,
    code     VARCHAR(16)  NOT NULL                ,
    name     VARCHAR(256) NOT NULL                ,
    UNIQUE      (code)                            ,
    UNIQUE      (name)                            ,
    PRIMARY KEY (id)
);

CREATE TABLE identity_providers (
    id       SERIAL                                         ,
    created  TIMESTAMP    NOT NULL                          ,
    deleted  TIMESTAMP                                      ,
    account  BIGINT       NOT NULL REFERENCES accounts (id) ,
    active   BOOLEAN      NOT NULL DEFAULT true             ,
    domain   VARCHAR(256) NOT NULL                          ,
    kind     VARCHAR(64)  NOT NULL                          ,
    code     VARCHAR(128) NOT NULL                          ,
    name     VARCHAR(256) NOT NULL                          ,
    UNIQUE      (account, domain)                           ,
    UNIQUE      (code)                                      ,
    PRIMARY KEY (id)
);

CREATE TABLE groups (
    id       SERIAL                                             ,
    app      BIGINT      NOT NULL REFERENCES applications (id)  ,
    created  TIMESTAMP   NOT NULL                               ,
    deleted  TIMESTAMP                                          ,
    code     VARCHAR(16) NOT NULL                              ,
    name     VARCHAR(64) NOT NULL                               ,
    UNIQUE      (app, code)                                     ,
    UNIQUE      (app, name)                                     ,
    PRIMARY KEY (id)
);

CREATE TABLE roles (
    id       SERIAL                                             ,
    created  TIMESTAMP    NOT NULL                              ,
    deleted  TIMESTAMP                                          ,
    app      BIGINT       NOT NULL REFERENCES applications (id) ,
    code     VARCHAR(16)  NOT NULL                              ,
    name     VARCHAR(32)  NOT NULL                              ,
    UNIQUE      (app, code)                                     ,
    UNIQUE      (app, name)                                     ,
    PRIMARY KEY (id)
);

CREATE TABLE permissions (
    id       SERIAL                                         ,
    created  TIMESTAMP    NOT NULL                          ,
    deleted  TIMESTAMP                                      ,
    rid      BIGINT       NOT NULL  REFERENCES roles (id)   ,
    code     VARCHAR(16)  NOT NULL                          ,
    name     VARCHAR(128) NOT NULL                          ,
    UNIQUE      (rid, code)                                 ,
    unique      (rid, name)                                 ,
    PRIMARY KEY (id)
);

CREATE TABLE account_to_app (
    acc     BIGINT     NOT NULL REFERENCES accounts     (id) ,
    app     BIGINT     NOT NULL REFERENCES applications (id) ,
    created TIMESTAMP  NOT NULL                              ,
    deleted TIMESTAMP                                        ,
    PRIMARY KEY (acc, app)
);

CREATE TABLE user_to_group (
    usr     BIGINT    NOT NULL REFERENCES users        (id) ,
    app     BIGINT    NOT NULL REFERENCES applications (id) ,
    grp     BIGINT    NOT NULL REFERENCES groups       (id) ,
    created TIMESTAMP NOT NULL                              ,
    deleted TIMESTAMP                                       ,
    PRIMARY KEY (usr, app, grp)
);

CREATE TABLE user_to_role (
    usr      BIGINT    NOT NULL REFERENCES users        (id)    ,
    app      BIGINT    NOT NULL REFERENCES applications (id)    ,
    rid      BIGINT    NOT NULL REFERENCES roles        (id)    ,
    created  TIMESTAMP NOT NULL                                 ,
    deleted  TIMESTAMP                                          ,
    PRIMARY KEY (usr, app, rid)
);