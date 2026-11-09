-- Presto: plano 'default' explícito e Presto Sign como plano que soma com os outros.
--
-- Antes, conta sem plano era tratada como plano padrão pelo console ("noPlan"), o que
-- impedia distinguir "Padrão + Sign" de "só Sign". Agora toda conta do Presto tem um
-- plano base explícito e as features da conta são a união das features dos seus planos:
--
--   default      : credentials, vault, 2fa, block, sign_documents
--   freemium_2fa : 2fa (sem mudança)
--   presto_sign  : presto_sign, vault, sign_documents
--
-- 'vault' libera o cofre de credenciais/certificados (o envelope precisa do certificado
-- no cofre); 'credentials' libera dashboard, sites e proxies.
--
-- Plano sem nenhuma feature some do token (join em plan_to_feature), por isso o 'default'
-- precisa ter as features antes de ser vinculado às contas.
--
-- Idempotente: pode ser rodado de novo.

BEGIN;

INSERT INTO features (created, app, code, name, description)
SELECT now(), a.id, f.code, f.name, f.description
  FROM applications a
 CROSS JOIN (VALUES
       ('credentials'   , 'Credenciais'          , 'Dashboard, sites e proxies'),
       ('vault'         , 'Cofre'                , 'Cofre de credenciais e certificados'),
       ('block'         , 'Bloqueios'            , 'Regras e bloqueios de domínios'),
       ('sign_documents', 'Assinatura individual', 'Assinatura individual de documentos e histórico')
     ) AS f(code, name, description)
 WHERE a.code = 'presto'
ON CONFLICT (app, code) DO NOTHING;

INSERT INTO plan_to_feature (created, plan, feature)
SELECT now(), p.id, f.id
  FROM plans p
  JOIN features f ON f.app = p.app
  JOIN applications a ON a.id = p.app
 WHERE a.code = 'presto'
   AND (p.code, f.code) IN (
       ('default'    , 'credentials'),
       ('default'    , 'vault'),
       ('default'    , '2fa'),
       ('default'    , 'block'),
       ('default'    , 'sign_documents'),
       ('presto_sign', 'vault'),
       ('presto_sign', 'sign_documents')
     )
ON CONFLICT (plan, feature) DO NOTHING;

-- Contas do Presto sem plano base (Start) passam a ter o 'default'. Contas que só têm o
-- 'presto_sign' hoje são Padrão + Sign e também recebem o 'default'.
INSERT INTO account_to_plan (created, acc, plan)
SELECT now(), aa.acc, p.id
  FROM account_to_app aa
  JOIN accounts a      ON a.id = aa.acc AND a.deleted IS NULL
  JOIN applications ap ON ap.id = aa.app AND ap.code = 'presto'
  JOIN plans p         ON p.app = ap.id AND p.code = 'default'
 WHERE aa.deleted IS NULL
   AND NOT EXISTS (
       SELECT 1
         FROM account_to_plan x
         JOIN plans px ON px.id = x.plan
        WHERE x.acc = aa.acc
          AND x.deleted IS NULL
          AND px.code IN ('default', 'freemium_2fa')
     )
ON CONFLICT (acc, plan) DO NOTHING;

COMMIT;
