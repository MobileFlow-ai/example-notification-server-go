WITH
operator_role AS (
    SELECT role.oid
      FROM pg_catalog.pg_roles AS role
     WHERE role.rolname = CURRENT_USER
),
migration_relation AS (
    SELECT relation.oid,
           relation.relkind,
           relation.relpersistence,
           relation.relrowsecurity,
           relation.relforcerowsecurity
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'public'
       AND relation.relname = 'schema_migrations'
),
migration_relation_shape AS (
    SELECT COALESCE((
        SELECT relation.relkind = 'r'
           AND relation.relpersistence = 'p'
           AND NOT relation.relrowsecurity
           AND NOT relation.relforcerowsecurity
           AND (
               SELECT pg_catalog.count(*) = 2
                  AND COALESCE(pg_catalog.bool_and(
                      (
                          attribute.attname = 'version'
                          AND attribute.atttypid =
                              'pg_catalog.int8'::pg_catalog.regtype
                          AND attribute.attnotnull
                      ) OR (
                          attribute.attname = 'dirty'
                          AND attribute.atttypid =
                              'pg_catalog.bool'::pg_catalog.regtype
                          AND attribute.attnotnull
                      )
                  ), FALSE)
                 FROM pg_catalog.pg_attribute AS attribute
                WHERE attribute.attrelid = relation.oid
                  AND attribute.attnum > 0
                  AND NOT attribute.attisdropped
           )
           AND (
               SELECT pg_catalog.count(*) = 1
                 FROM pg_catalog.pg_constraint AS constraint_record
                WHERE constraint_record.conrelid = relation.oid
                  AND constraint_record.contype = 'p'
                  AND constraint_record.conkey = ARRAY[
                      (
                          SELECT attribute.attnum
                            FROM pg_catalog.pg_attribute AS attribute
                           WHERE attribute.attrelid = relation.oid
                             AND attribute.attname = 'version'
                             AND NOT attribute.attisdropped
                      )
                  ]::pg_catalog.int2[]
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_catalog.pg_policy AS policy
                WHERE policy.polrelid = relation.oid
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_catalog.pg_rewrite AS rewrite_rule
                WHERE rewrite_rule.ev_class = relation.oid
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_catalog.pg_trigger AS trigger
                WHERE trigger.tgrelid = relation.oid
                  AND NOT trigger.tgisinternal
           )
          FROM migration_relation AS relation
    ), FALSE) AS ready
),
legacy_relation_shape AS (
    SELECT pg_catalog.count(*) = 4
       AND COALESCE(pg_catalog.bool_and(
           relation.relkind = 'r'
           AND relation.relpersistence = 'p'
           AND relation.relowner = operator_role.oid
       ), FALSE) AS ready
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
      CROSS JOIN operator_role
     WHERE namespace.nspname = 'public'
       AND relation.relname IN (
           'installations',
           'device_delivery_mechanisms',
           'subscriptions',
           'subscription_hmac_keys'
       )
),
marker_relation AS (
    SELECT relation.oid,
           relation.relkind,
           relation.relpersistence,
           relation.relowner,
           relation.relrowsecurity,
           relation.relforcerowsecurity
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = relation.relnamespace
     WHERE namespace.nspname = 'hytch_push_vault'
       AND relation.relname = 'legacy_routing_activation'
),
marker_relation_shape AS (
    SELECT COALESCE((
        SELECT relation.relkind = 'r'
           AND relation.relpersistence = 'p'
           AND relation.relowner = operator_role.oid
           AND NOT relation.relrowsecurity
           AND NOT relation.relforcerowsecurity
           AND (
               SELECT pg_catalog.count(*) = 2
                  AND COALESCE(pg_catalog.bool_and(
                      (
                          attribute.attname = 'singleton'
                          AND attribute.atttypid =
                              'pg_catalog.bool'::pg_catalog.regtype
                          AND attribute.attnotnull
                      ) OR (
                          attribute.attname = 'activated_at'
                          AND attribute.atttypid =
                              'pg_catalog.timestamptz'::pg_catalog.regtype
                          AND attribute.attnotnull
                      )
                  ), FALSE)
                 FROM pg_catalog.pg_attribute AS attribute
                WHERE attribute.attrelid = relation.oid
                  AND attribute.attnum > 0
                  AND NOT attribute.attisdropped
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_catalog.pg_policy AS policy
                WHERE policy.polrelid = relation.oid
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_catalog.pg_rewrite AS rewrite_rule
                WHERE rewrite_rule.ev_class = relation.oid
           )
          FROM marker_relation AS relation
          CROSS JOIN operator_role
    ), FALSE) AS ready
),
activation_function_shape AS (
    SELECT pg_catalog.count(*) = 2
       AND COALESCE(pg_catalog.bool_and(
           routine.proowner = operator_role.oid
           AND routine.prokind = 'f'
           AND routine.prosecdef
           AND NOT routine.proleakproof
           AND NOT routine.proisstrict
           AND NOT routine.proretset
           AND routine.provolatile = 'v'
           AND routine.proparallel = 'u'
           AND routine.proconfig =
               ARRAY['search_path=pg_catalog']::pg_catalog.text[]
           AND language.lanname = 'plpgsql'
           AND (
               (
                   routine.proname = 'reject_legacy_routing_mutation'
                   AND routine.prorettype =
                       'pg_catalog.trigger'::pg_catalog.regtype
                   AND routine.pronargs = 0
                   AND routine.pronargdefaults = 0
                   AND routine.proargtypes =
                       ''::pg_catalog.oidvector
                   AND routine.prosrc = $source$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'legacy plaintext routing is disabled';
END;
$source$
               ) OR (
                   routine.proname =
                       'activate_legacy_routing_retirement'
                   AND routine.prorettype =
                       'pg_catalog.void'::pg_catalog.regtype
                   AND routine.pronargs = 1
                   AND routine.pronargdefaults = 0
                   AND routine.proargtypes[0] =
                       'pg_catalog.text'::pg_catalog.regtype
                   AND routine.prosrc = $activation_source$
DECLARE
    required_confirmation TEXT;
    activation_owner OID;
BEGIN
    required_confirmation :=
        'RETIRE LEGACY PLAINTEXT ROUTING FROM ' || current_database();
    IF confirmation IS DISTINCT FROM required_confirmation THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'legacy routing retirement confirmation invalid';
    END IF;

    SELECT routine.proowner
      INTO activation_owner
      FROM pg_catalog.pg_proc AS routine
     WHERE routine.oid =
           'hytch_push_vault.activate_legacy_routing_retirement(text)'
               ::pg_catalog.regprocedure
       AND routine.pronargdefaults = 0;

    IF activation_owner IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy activation function preflight failed';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_subscription AS subscription
         WHERE subscription.subdbid = (
             SELECT database.oid
               FROM pg_catalog.pg_database AS database
              WHERE database.datname = current_database()
         )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'logical replication subscription blocks retirement';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_event_trigger AS event_trigger
         WHERE event_trigger.evtenabled <> 'D'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'enabled event trigger blocks retirement';
    END IF;

    LOCK TABLE
        public.installations,
        public.device_delivery_mechanisms,
        public.subscriptions,
        public.subscription_hmac_keys
    IN ACCESS EXCLUSIVE MODE;
    LOCK TABLE hytch_push_vault.legacy_routing_activation
    IN ACCESS EXCLUSIVE MODE;

    IF (
        SELECT COUNT(*) <> 4 OR
               NOT BOOL_AND(
                   relation.relkind = 'r' AND
                   relation.relpersistence = 'p' AND
                   relation.relowner = activation_owner
               )
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'public'
           AND relation.relname IN (
               'installations',
               'device_delivery_mechanisms',
               'subscriptions',
               'subscription_hmac_keys'
           )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy routing relation preflight failed';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS relation
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = relation.relnamespace
          JOIN pg_catalog.pg_proc AS routine
            ON routine.oid =
               'hytch_push_vault.reject_legacy_routing_mutation()'
                   ::pg_catalog.regprocedure
          JOIN pg_catalog.pg_language AS language
            ON language.oid = routine.prolang
         WHERE namespace.nspname = 'hytch_push_vault'
           AND relation.relname = 'legacy_routing_activation'
           AND relation.relkind = 'r'
           AND relation.relpersistence = 'p'
           AND relation.relowner = activation_owner
           AND NOT relation.relrowsecurity
           AND NOT relation.relforcerowsecurity
           AND (
               SELECT pg_catalog.count(*) = 2
                  AND COALESCE(pg_catalog.bool_and(
                      (
                          attribute.attname = 'singleton'
                          AND attribute.atttypid =
                              'pg_catalog.bool'::pg_catalog.regtype
                          AND attribute.attnotnull
                      ) OR (
                          attribute.attname = 'activated_at'
                          AND attribute.atttypid =
                              'pg_catalog.timestamptz'::pg_catalog.regtype
                          AND attribute.attnotnull
                      )
                  ), FALSE)
                 FROM pg_catalog.pg_attribute AS attribute
                WHERE attribute.attrelid = relation.oid
                  AND attribute.attnum > 0
                  AND NOT attribute.attisdropped
           )
           AND routine.proowner = activation_owner
           AND routine.prokind = 'f'
           AND routine.prorettype =
               'pg_catalog.trigger'::pg_catalog.regtype
           AND routine.pronargs = 0
           AND routine.pronargdefaults = 0
           AND routine.proargtypes =
               ''::pg_catalog.oidvector
           AND routine.prosecdef
           AND NOT routine.proleakproof
           AND NOT routine.proisstrict
           AND NOT routine.proretset
           AND routine.provolatile = 'v'
           AND routine.proparallel = 'u'
           AND routine.proconfig = ARRAY[
               'search_path=pg_catalog'
           ]::TEXT[]
           AND language.lanname = 'plpgsql'
           AND routine.prosrc = $source$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'legacy plaintext routing is disabled';
END;
$source$
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_catalog.aclexplode(
                     COALESCE(
                         routine.proacl,
                         pg_catalog.acldefault(
                             'f',
                             routine.proowner
                         )
                     )
                 ) AS privilege
                WHERE privilege.grantee = 0
                  AND privilege.privilege_type = 'EXECUTE'
           )
    ) OR EXISTS (
        SELECT 1
          FROM pg_catalog.pg_policy AS policy
         WHERE policy.polrelid =
               'hytch_push_vault.legacy_routing_activation'
                   ::pg_catalog.regclass
    ) OR EXISTS (
        SELECT 1
          FROM pg_catalog.pg_rewrite AS rewrite_rule
         WHERE rewrite_rule.ev_class =
               'hytch_push_vault.legacy_routing_activation'
                   ::pg_catalog.regclass
    ) OR (
        SELECT COUNT(*)
          FROM pg_catalog.pg_trigger AS trigger
         WHERE trigger.tgrelid =
               'hytch_push_vault.legacy_routing_activation'
                   ::pg_catalog.regclass
           AND NOT trigger.tgisinternal
    ) <> 3 OR (
        WITH expected (trigger_name, trigger_type) AS (
            VALUES
                ('hytch_legacy_activation_insert_guard', 6),
                ('hytch_legacy_activation_dml_guard', 27),
                ('hytch_legacy_activation_truncate_guard', 34)
        )
        SELECT COUNT(*)
          FROM expected
          JOIN pg_catalog.pg_trigger AS trigger
            ON trigger.tgrelid =
               'hytch_push_vault.legacy_routing_activation'
                   ::pg_catalog.regclass
           AND trigger.tgname = expected.trigger_name
          JOIN pg_catalog.pg_proc AS routine
            ON routine.oid = trigger.tgfoid
         WHERE NOT trigger.tgisinternal
           AND trigger.tgenabled = 'A'
           AND trigger.tgtype = expected.trigger_type
           AND trigger.tgqual IS NULL
           AND trigger.tgnargs = 0
           AND pg_catalog.octet_length(trigger.tgargs) = 0
           AND trigger.tgattr::TEXT = ''
           AND trigger.tgoldtable IS NULL
           AND trigger.tgnewtable IS NULL
           AND trigger.tgconstraint = 0
           AND NOT trigger.tgdeferrable
           AND NOT trigger.tginitdeferred
           AND routine.oid =
               'hytch_push_vault.reject_legacy_routing_mutation()'
                   ::pg_catalog.regprocedure
    ) <> 3 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy activation marker preflight failed';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM hytch_push_vault.legacy_routing_activation
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy plaintext routing is already disabled';
    END IF;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_event_trigger AS event_trigger
         WHERE event_trigger.evtenabled <> 'D'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'enabled event trigger blocks retirement';
    END IF;

    REVOKE CREATE ON SCHEMA public FROM PUBLIC;

    IF EXISTS (
        SELECT 1
          FROM pg_catalog.pg_namespace AS namespace
          CROSS JOIN LATERAL pg_catalog.aclexplode(
              COALESCE(
                  namespace.nspacl,
                  pg_catalog.acldefault(
                      'n',
                      namespace.nspowner
                  )
              )
          ) AS privilege
         WHERE namespace.nspname = 'public'
           AND privilege.privilege_type = 'CREATE'
           AND privilege.grantee <> namespace.nspowner
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy routing schema privilege preflight failed';
    END IF;

    DROP TABLE public.subscription_hmac_keys;
    DROP TABLE public.subscriptions;
    DROP TABLE public.device_delivery_mechanisms;
    DROP TABLE public.installations;

    IF to_regclass('public.installations') IS NOT NULL OR
       to_regclass('public.device_delivery_mechanisms') IS NOT NULL OR
       to_regclass('public.subscriptions') IS NOT NULL OR
       to_regclass('public.subscription_hmac_keys') IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy routing relation retirement incomplete';
    END IF;

    ALTER TABLE hytch_push_vault.legacy_routing_activation
        DISABLE TRIGGER hytch_legacy_activation_insert_guard;
    INSERT INTO hytch_push_vault.legacy_routing_activation (
        singleton,
        activated_at
    ) VALUES (
        TRUE,
        clock_timestamp()
    );
    ALTER TABLE hytch_push_vault.legacy_routing_activation
        ENABLE ALWAYS TRIGGER hytch_legacy_activation_insert_guard;
END;
$activation_source$
               )
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_catalog.aclexplode(
                     COALESCE(
                         routine.proacl,
                         pg_catalog.acldefault('f', routine.proowner)
                     )
                 ) AS privilege
                WHERE privilege.grantee <> routine.proowner
                  AND privilege.privilege_type = 'EXECUTE'
           )
       ), FALSE) AS ready
      FROM pg_catalog.pg_proc AS routine
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = routine.pronamespace
      JOIN pg_catalog.pg_language AS language
        ON language.oid = routine.prolang
      CROSS JOIN operator_role
     WHERE namespace.nspname = 'hytch_push_vault'
       AND routine.proname IN (
           'reject_legacy_routing_mutation',
           'activate_legacy_routing_retirement'
       )
),
expected_marker_triggers (trigger_name, trigger_type) AS (
    VALUES
        ('hytch_legacy_activation_insert_guard', 6),
        ('hytch_legacy_activation_dml_guard', 27),
        ('hytch_legacy_activation_truncate_guard', 34)
),
marker_trigger_shape AS (
    SELECT (
        SELECT pg_catalog.count(*) = 3
          FROM pg_catalog.pg_trigger AS trigger
          JOIN marker_relation AS relation
            ON relation.oid = trigger.tgrelid
         WHERE NOT trigger.tgisinternal
    ) AND (
        SELECT pg_catalog.count(*) = 3
          FROM expected_marker_triggers AS expected
          JOIN pg_catalog.pg_trigger AS trigger
            ON trigger.tgname = expected.trigger_name
           AND trigger.tgtype = expected.trigger_type
          JOIN marker_relation AS relation
            ON relation.oid = trigger.tgrelid
          JOIN pg_catalog.pg_proc AS routine
            ON routine.oid = trigger.tgfoid
          JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = routine.pronamespace
         WHERE NOT trigger.tgisinternal
           AND trigger.tgenabled = 'A'
           AND trigger.tgqual IS NULL
           AND trigger.tgnargs = 0
           AND pg_catalog.octet_length(trigger.tgargs) = 0
           AND trigger.tgattr::pg_catalog.text = ''
           AND trigger.tgoldtable IS NULL
           AND trigger.tgnewtable IS NULL
           AND trigger.tgconstraint = 0
           AND NOT trigger.tgdeferrable
           AND NOT trigger.tginitdeferred
           AND namespace.nspname = 'hytch_push_vault'
           AND routine.proname = 'reject_legacy_routing_mutation'
           AND routine.pronargs = 0
           AND routine.pronargdefaults = 0
           AND routine.proargtypes = ''::pg_catalog.oidvector
    ) AS ready
),
checks AS (
    SELECT
        pg_catalog.current_setting('transaction_read_only') = 'on'
            AS transaction_read_only,
        migration_relation_shape.ready
            AND (
                SELECT pg_catalog.count(*) = 1
                   AND COALESCE(pg_catalog.bool_and(
                       migration.version = 13
                       AND NOT migration.dirty
                   ), FALSE)
                  FROM public.schema_migrations AS migration
            ) AS schema_migrations_ready,
        NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_stat_activity AS activity
             WHERE activity.datid = (
                 SELECT database.oid
                   FROM pg_catalog.pg_database AS database
                  WHERE database.datname =
                      pg_catalog.current_database()
             )
               AND activity.pid <> pg_catalog.pg_backend_pid()
               AND activity.backend_type = 'client backend'
        ) AS only_client_session,
        NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_subscription AS subscription
             WHERE subscription.subdbid = (
                 SELECT database.oid
                   FROM pg_catalog.pg_database AS database
                  WHERE database.datname =
                      pg_catalog.current_database()
             )
        ) AS no_logical_subscription,
        NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_event_trigger AS event_trigger
             WHERE event_trigger.evtenabled <> 'D'
        ) AS no_enabled_event_trigger,
        legacy_relation_shape.ready AS legacy_relations_ready,
        marker_relation_shape.ready
            AND NOT EXISTS (
                SELECT 1
                  FROM hytch_push_vault.legacy_routing_activation
            ) AS activation_marker_empty,
        activation_function_shape.ready AS activation_functions_ready,
        marker_trigger_shape.ready AS activation_triggers_ready,
        NOT EXISTS (
            SELECT 1
              FROM pg_catalog.pg_namespace AS namespace
              CROSS JOIN LATERAL pg_catalog.aclexplode(
                  COALESCE(
                      namespace.nspacl,
                      pg_catalog.acldefault('n', namespace.nspowner)
                  )
              ) AS privilege
             WHERE namespace.nspname = 'public'
               AND privilege.privilege_type = 'CREATE'
               AND privilege.grantee <> 0
               AND privilege.grantee <> namespace.nspowner
        ) AS no_named_non_owner_public_create
      FROM migration_relation_shape
      CROSS JOIN legacy_relation_shape
      CROSS JOIN marker_relation_shape
      CROSS JOIN activation_function_shape
      CROSS JOIN marker_trigger_shape
)
SELECT pg_catalog.current_database(),
       checks.transaction_read_only,
       checks.schema_migrations_ready,
       checks.only_client_session,
       checks.no_logical_subscription,
       checks.no_enabled_event_trigger,
       checks.legacy_relations_ready,
       checks.activation_marker_empty,
       checks.activation_functions_ready,
       checks.activation_triggers_ready,
       checks.no_named_non_owner_public_create,
       checks.transaction_read_only
           AND checks.schema_migrations_ready
           AND checks.only_client_session
           AND checks.no_logical_subscription
           AND checks.no_enabled_event_trigger
           AND checks.legacy_relations_ready
           AND checks.activation_marker_empty
           AND checks.activation_functions_ready
           AND checks.activation_triggers_ready
           AND checks.no_named_non_owner_public_create AS all_ready
  FROM checks;
