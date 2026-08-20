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

INSERT INTO groups (created, acc, app, code, name) VALUES (now(), 1, 1 /* Console */, 'g1', 'G1 - Console');
INSERT INTO groups (created, acc, app, code, name) VALUES (now(), 1, 2 /* Presto */ , 'g1', 'G1 - Presto');
INSERT INTO groups (created, acc, app, code, name) VALUES (now(), 1, 2 /* Presto */ , 'g2', 'G2 - Presto' );

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

INSERT INTO group_to_role (created, grp, rid) VALUES (now(), 1 /* Console */, 1 /* Global Admin */);
INSERT INTO group_to_role (created, grp, rid) VALUES (now(), 2 /* Presto */ , 4 /* Credentials Admin */);
INSERT INTO group_to_role (created, grp, rid) VALUES (now(), 2 /* Presto */ , 5 /* Policy Admin */);

-- Presto features (app id = 2)
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'dashboard'  , 'Dashboard'         , 'Página inicial e métricas');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'tfa'        , '2FA'               , 'Cadastro e compartilhamento de códigos TOTP');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'credentials', 'Credenciais'       , 'Gestão de credenciais e cofre');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'sites'      , 'Sites'             , 'Catálogo de sites e domínios');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'groups'     , 'Usuários e Grupos' , 'Administração de usuários e grupos');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'directives' , 'Diretivas'         , 'Regras de manipulação de páginas');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'rules'      , 'Regras'            , 'Regras de acesso e políticas');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'proxies'    , 'Proxies'           , 'Configuração de proxies');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'signing'    , 'Assinaturas'       , 'Assinatura de documentos');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'express'    , 'Express'           , 'Autopreenchimento e login expresso');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'sessions'   , 'Sessões'           , 'Ponte de sessões de emergência');
INSERT INTO features (created, app, code, name, description) VALUES (now(), 2, 'config'     , 'Configurações'     , 'Configurações e perfil');

-- Presto plans
INSERT INTO plans (created, app, code, name, description) VALUES (now(), 2, 'legacy'      , 'Legacy'        , 'Plano completo aplicado a todas as contas existentes');
INSERT INTO plans (created, app, code, name, description) VALUES (now(), 2, '2fa_freemium', '2FA Freemium'  , 'Plano gratuito: somente cadastro e compartilhamento de 2FA');

-- plan_to_feature: legacy = all 12 features (ids 1..12), 2fa_freemium = tfa only (id 2)
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 1  /* dashboard   */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 2  /* tfa         */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 3  /* credentials */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 4  /* sites       */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 5  /* groups      */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 6  /* directives  */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 7  /* rules       */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 8  /* proxies     */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 9  /* signing     */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 10 /* express     */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 11 /* sessions    */);
INSERT INTO plan_to_feature (created, plan, feature) VALUES (now(), 1 /* legacy */, 12 /* config      */);
INSERT INTO plan_to_feature (created, plan, feature, value) VALUES (now(), 2 /* 2fa_freemium */, 2 /* tfa */, 5 /* max shared 2FA codes */);

-- Existing presto-bearing accounts default to legacy (mirrors M7 backfill behaviour for the dev DB)
INSERT INTO account_to_plan (created, acc, plan) VALUES (now(), 1 /* A1 */, 1 /* legacy */);