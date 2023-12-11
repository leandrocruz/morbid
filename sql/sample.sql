INSERT INTO tenants (created, code, name) VALUES (now(), 'DEFAULT', 'Default Tenant');
INSERT INTO tenants (created, code, name) VALUES (now(), 'T2', 'Tenant T2');
INSERT INTO tenants (created, code, name) VALUES (now(), 'T3', 'Tenant T3');

INSERT INTO applications (created, code, name) VALUES (now(), 'console', 'Console');
INSERT INTO applications (created, code, name) VALUES (now(), 'presto' , 'Presto');
INSERT INTO applications (created, code, name) VALUES (now(), 'app'    , 'APP');

INSERT INTO accounts (created, tenant, code, name) VALUES (now(), 1, 'a1', 'A1');
INSERT INTO accounts (created, tenant, code, name) VALUES (now(), 1, 'a2', 'A2');
INSERT INTO accounts (created, tenant, code, name) VALUES (now(), 2, 'a3', 'A3');
INSERT INTO accounts (created, tenant, code, name) VALUES (now(), 2, 'a4', 'A4');

INSERT INTO users (created, account, code, email)        VALUES (now(), 1 /* A1 */, 'UID1', 'user1@0.com');
INSERT INTO users (created, account, code, email)        VALUES (now(), 1 /* A1 */, 'UID2', 'user2@0.com');
INSERT INTO users (created, account, code, email, kind)  VALUES (now(), 1 /* A1 */, 'UID3', 'sa1@0.com', 'SA');
INSERT INTO users (created, account, code, email)        VALUES (now(), 2 /* A2 */, 'UID4', 'user1@1.com');

INSERT INTO identity_providers (created, account, domain, kind, code, name) VALUES (now(), 1, 'oystr.com.br', 'SAML', 'saml.presto-saml-test', 'Oystr Robôs Inteligentes');
INSERT INTO identity_providers (created, account, domain, kind, code, name) VALUES (now(), 1, 'dogma.legal' , 'SAML', 'saml.dogma'           , 'Dogma Data Privacy');

INSERT INTO account_to_app (created, acc, app) values (now(), 1 /* A1 */, 1 /* Console */ );
INSERT INTO account_to_app (created, acc, app) values (now(), 1 /* A1 */, 2 /* Presto */  );
INSERT INTO account_to_app (created, acc, app) values (now(), 2 /* A2 */, 3 /* APP */     );

INSERT INTO groups (created, app, code, name) VALUES (now(), 1 /* Console */, 'g1', 'G1 - Console');
INSERT INTO groups (created, app, code, name) VALUES (now(), 2 /* Presto */ , 'g1', 'G1 - Presto');
INSERT INTO groups (created, app, code, name) VALUES (now(), 2 /* Presto */ , 'g2', 'G2 - Presto' );

INSERT INTO user_to_group (created, usr, app, grp) VALUES (now(), 1, 1 /* Console */, 1 /* G1 - Console */);
INSERT INTO user_to_group (created, usr, app, grp) VALUES (now(), 1, 2 /* Presto */,  2 /* G1 - Presto */);

INSERT INTO roles (created, app, code, name) VALUES (now(), 1 /* Console */, 'adm'       , 'Global Admin');
INSERT INTO roles (created, app, code, name) VALUES (now(), 1 /* Console */, 'cred_adm'  , 'Credentials Admin');
INSERT INTO roles (created, app, code, name) VALUES (now(), 2 /* Presto */ , 'adm'       , 'Global Admin');
INSERT INTO roles (created, app, code, name) VALUES (now(), 2 /* Presto */ , 'cred_adm'  , 'Credentials Admin');
INSERT INTO roles (created, app, code, name) VALUES (now(), 2 /* Presto */ , 'policy_adm', 'Policy Admin');

INSERT INTO permissions (created, rid, code, name) VALUES (now(), 1, 'create', 'Create');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 1, 'read'  , 'Read');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 1, 'update', 'Update');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 1, 'delete', 'Delete');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 2, 'create', 'Create');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 2, 'read'  , 'Read');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 2, 'update', 'Update');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 2, 'delete', 'Delete');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 3, 'create', 'Create');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 3, 'read'  , 'Read');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 3, 'update', 'Update');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 3, 'delete', 'Delete');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 4, 'create', 'Create');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 4, 'read'  , 'Read');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 4, 'update', 'Update');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 4, 'delete', 'Delete');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 5, 'create', 'Create');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 5, 'read'  , 'Read');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 5, 'update', 'Update');
INSERT INTO permissions (created, rid, code, name) VALUES (now(), 5, 'delete', 'Delete');

INSERT INTO user_to_role (created, usr, app, rid) VALUES (now(), 1, 1 /* Console */, 1 /* Global Admin */);
INSERT INTO user_to_role (created, usr, app, rid) VALUES (now(), 1, 2 /* Presto */ , 4 /* Credentials Admin */);
INSERT INTO user_to_role (created, usr, app, rid) VALUES (now(), 1, 2 /* Presto */ , 5 /* Policy Admin */);