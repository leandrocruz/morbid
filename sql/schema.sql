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
    acc      BIGINT      NOT NULL REFERENCES accounts     (id)  ,
    app      BIGINT      NOT NULL REFERENCES applications (id)  ,
    created  TIMESTAMP   NOT NULL                               ,
    deleted  TIMESTAMP                                          ,
    code     VARCHAR(16) NOT NULL                               ,
    name     VARCHAR(64) NOT NULL                               ,
    UNIQUE      (acc, app, code)                                ,
    UNIQUE      (acc, app, name)                                ,
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

CREATE TABLE group_to_role (
    grp      BIGINT    NOT NULL REFERENCES groups (id) ,
    rid      BIGINT    NOT NULL REFERENCES roles  (id) ,
    created  TIMESTAMP NOT NULL                        ,
    deleted TIMESTAMP                                  ,
    PRIMARY KEY (grp, rid)
);

CREATE TABLE features (
    id          SERIAL                                            ,
    created     TIMESTAMP    NOT NULL                             ,
    deleted     TIMESTAMP                                         ,
    app         BIGINT       NOT NULL REFERENCES applications(id) ,
    code        VARCHAR(32)  NOT NULL                             ,
    name        VARCHAR(128) NOT NULL                             ,
    description TEXT                                              ,
    UNIQUE      (app, code)                                       ,
    PRIMARY KEY (id)
);

CREATE TABLE plans (
    id          SERIAL                                            ,
    created     TIMESTAMP    NOT NULL                             ,
    deleted     TIMESTAMP                                         ,
    active      BOOLEAN      NOT NULL DEFAULT true                ,
    app         BIGINT       NOT NULL REFERENCES applications(id) ,
    code        VARCHAR(32)  NOT NULL                             ,
    name        VARCHAR(128) NOT NULL                             ,
    description TEXT                                              ,
    UNIQUE      (app, code)                                       ,
    PRIMARY KEY (id)
);

CREATE TABLE plan_to_feature (
    plan    BIGINT    NOT NULL REFERENCES plans    (id) ,
    feature BIGINT    NOT NULL REFERENCES features (id) ,
    value   BIGINT                                      ,
    created TIMESTAMP NOT NULL                          ,
    deleted TIMESTAMP                                   ,
    PRIMARY KEY (plan, feature)
);

CREATE TABLE account_to_plan (
    acc     BIGINT    NOT NULL REFERENCES accounts (id) ,
    plan    BIGINT    NOT NULL REFERENCES plans    (id) ,
    created TIMESTAMP NOT NULL                          ,
    deleted TIMESTAMP                                   ,
    PRIMARY KEY (acc, plan)
);

-- Supporting indexes for plan/feature lookups.
--   account_to_plan PK(acc, plan)        already covers lookups by acc (FindPlansForAccount).
--   plan_to_feature PK(plan, feature)    already covers lookups by plan (plan -> features join).
-- The indexes below cover the *reverse* directions (plan -> accounts, feature -> plans)
-- and the app-scoped lookups used to list plans/features per application.
CREATE INDEX account_to_plan_plan_idx ON account_to_plan (plan);
CREATE INDEX plan_to_feature_feature_idx ON plan_to_feature (feature);
CREATE INDEX plans_app_idx ON plans (app);
CREATE INDEX features_app_idx ON features (app);