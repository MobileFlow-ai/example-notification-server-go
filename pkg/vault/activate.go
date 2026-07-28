package vault

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
)

var ErrLegacyPlaintextRoutingEnabled = errors.New(
	"legacy plaintext routing is not disabled",
)
var ErrLegacyRoutingBarrierInvalid = errors.New(
	"legacy plaintext routing barrier is invalid",
)

const (
	rejectLegacyRoutingSourceSHA256 = "f5bb3a1e800aa0d2cd92be9e8844e90d" +
		"f1b12d6550642dc1562287fe25e86137"
	activateLegacyRoutingSourceSHA256 = "eb9c48abb59f1b2229365b1c3550d3ae" +
		"fe4e9753b8d05f6ec1f7cae43bae5b52"
)

// RequireLegacyPlaintextRoutingDisabled verifies the database-wide activation
// marker and the irreversible absence of every legacy plaintext routing
// relation. The one-shot maintenance function drops those relations without
// CASCADE, so logical apply, replica-role sessions, stale snapshots, RLS,
// rewrite rules, and row triggers cannot reopen a plaintext write path.
//
// Routine secure startup is deliberately read-only and also verifies the
// exact marker triggers/function bodies, rejects logical subscriptions, and
// requires a restricted non-owner runtime role.
func (s *Store) RequireLegacyPlaintextRoutingDisabled(
	ctx context.Context,
) error {
	if s == nil || s.db == nil {
		return ErrStoreUnavailable
	}

	var activated bool
	var legacyRelationsAbsent bool
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT
		     (
		         SELECT pg_catalog.count(*) = 1 AND
		                COALESCE(
		                    pg_catalog.bool_and(singleton),
		                    FALSE
		                )
		           FROM hytch_push_vault.legacy_routing_activation
		     ),
		     pg_catalog.to_regclass('public.installations') IS NULL AND
		     pg_catalog.to_regclass(
		         'public.device_delivery_mechanisms'
		     ) IS NULL AND
		     pg_catalog.to_regclass('public.subscriptions') IS NULL AND
		     pg_catalog.to_regclass(
		         'public.subscription_hmac_keys'
		     ) IS NULL`,
	).Scan(&activated, &legacyRelationsAbsent); err != nil {
		return ErrStoreUnavailable
	}
	if !activated || !legacyRelationsAbsent {
		return ErrLegacyPlaintextRoutingEnabled
	}

	var (
		markerValid             bool
		totalTriggerCount       int
		exactTriggerCount       int
		rejectFunctionValid     bool
		activationFunctionValid bool
		rejectSource            sql.NullString
		activationSource        sql.NullString
		noLogicalSubscription   bool
		schemaPrivilegesValid   bool
	)
	if err := s.db.QueryRowContext(
		ctx,
		`WITH marker_relation AS (
		     SELECT relation.*
		       FROM pg_catalog.pg_class AS relation
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = relation.relnamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND relation.relname = 'legacy_routing_activation'
		 ),
		 reject_routine AS (
		     SELECT routine.*
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND routine.proname =
		            'reject_legacy_routing_mutation'
		        AND routine.pronargs = 0
		 ),
		 activation_routine AS (
		     SELECT routine.*
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND routine.proname =
		            'activate_legacy_routing_retirement'
		        AND routine.pronargs = 1
		        AND routine.proargtypes[0] =
		            'pg_catalog.text'::pg_catalog.regtype
		 ),
		 expected_trigger (trigger_name, trigger_type) AS (
		     VALUES
		         (
		             'hytch_legacy_activation_insert_guard',
		             6::pg_catalog.int2
		         ),
		         (
		             'hytch_legacy_activation_dml_guard',
		             27::pg_catalog.int2
		         ),
		         (
		             'hytch_legacy_activation_truncate_guard',
		             34::pg_catalog.int2
		         )
		 )
		 SELECT
		     COALESCE((
		         SELECT
		             marker.relkind = 'r' AND
		             marker.relpersistence = 'p' AND
		             NOT marker.relrowsecurity AND
		             NOT marker.relforcerowsecurity AND
		             marker.relowner = reject.proowner AND
		             marker.relowner = activation.proowner AND
		             (
		                 SELECT pg_catalog.count(*) = 2 AND
		                        COALESCE(pg_catalog.bool_and(
		                            (
		                                attribute.attname =
		                                    'singleton' AND
		                                attribute.atttypid =
		                                    'pg_catalog.bool'
		                                        ::pg_catalog.regtype AND
		                                attribute.attnotnull
		                            ) OR (
		                                attribute.attname =
		                                    'activated_at' AND
		                                attribute.atttypid =
		                                    'pg_catalog.timestamptz'
		                                        ::pg_catalog.regtype AND
		                                attribute.attnotnull
		                            )
		                        ), FALSE)
		                   FROM pg_catalog.pg_attribute AS attribute
		                  WHERE attribute.attrelid = marker.oid
		                    AND attribute.attnum > 0
		                    AND NOT attribute.attisdropped
		             ) AND
		             NOT EXISTS (
		                 SELECT 1
		                   FROM pg_catalog.pg_policy AS policy
		                  WHERE policy.polrelid = marker.oid
		             ) AND
		             NOT EXISTS (
		                 SELECT 1
		                   FROM pg_catalog.pg_rewrite AS rewrite_rule
		                  WHERE rewrite_rule.ev_class = marker.oid
		             )
		           FROM marker_relation AS marker
		           JOIN reject_routine AS reject ON TRUE
		           JOIN activation_routine AS activation ON TRUE
		     ), FALSE),
		     (
		         SELECT pg_catalog.count(*)
		           FROM pg_catalog.pg_trigger AS trigger
		           JOIN marker_relation AS marker
		             ON marker.oid = trigger.tgrelid
		          WHERE NOT trigger.tgisinternal
		     ),
		     (
		         SELECT pg_catalog.count(*)
		           FROM expected_trigger AS expected
		           JOIN marker_relation AS marker ON TRUE
		           JOIN pg_catalog.pg_trigger AS trigger
		             ON trigger.tgrelid = marker.oid
		            AND trigger.tgname = expected.trigger_name
		           JOIN reject_routine AS reject
		             ON reject.oid = trigger.tgfoid
		          WHERE NOT trigger.tgisinternal
		            AND trigger.tgenabled = 'A'
		            AND trigger.tgtype = expected.trigger_type
		            AND trigger.tgqual IS NULL
		            AND trigger.tgnargs = 0
		            AND pg_catalog.octet_length(trigger.tgargs) = 0
		            AND trigger.tgattr::pg_catalog.text = ''
		            AND trigger.tgoldtable IS NULL
		            AND trigger.tgnewtable IS NULL
		            AND trigger.tgconstraint = 0
		            AND NOT trigger.tgdeferrable
		            AND NOT trigger.tginitdeferred
		     ),
		     (
		         SELECT pg_catalog.count(*) = 1
		           FROM reject_routine AS routine
		           JOIN pg_catalog.pg_language AS language
		             ON language.oid = routine.prolang
		          WHERE routine.prokind = 'f'
		            AND routine.prorettype =
		                'pg_catalog.trigger'::pg_catalog.regtype
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
		            ]::pg_catalog.text[]
		            AND language.lanname = 'plpgsql'
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
		                 WHERE privilege.privilege_type = 'EXECUTE'
		                   AND privilege.grantee <> routine.proowner
		            )
		     ),
		     (
		         SELECT pg_catalog.count(*) = 1
		           FROM activation_routine AS routine
		           JOIN pg_catalog.pg_language AS language
		             ON language.oid = routine.prolang
		          WHERE routine.prokind = 'f'
		            AND routine.prorettype =
		                'pg_catalog.void'::pg_catalog.regtype
		            AND routine.prosecdef
		            AND NOT routine.proleakproof
		            AND NOT routine.proisstrict
		            AND NOT routine.proretset
		            AND routine.provolatile = 'v'
		            AND routine.proparallel = 'u'
		            AND routine.proconfig = ARRAY[
		                'search_path=pg_catalog'
		            ]::pg_catalog.text[]
		            AND language.lanname = 'plpgsql'
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
		                 WHERE privilege.privilege_type = 'EXECUTE'
		                   AND privilege.grantee <> routine.proowner
		            )
		     ),
		     (
		         SELECT pg_catalog.max(routine.prosrc)
		           FROM reject_routine AS routine
		     ),
		     (
		         SELECT pg_catalog.max(routine.prosrc)
		           FROM activation_routine AS routine
		     ),
		     NOT EXISTS (
		         SELECT 1
		           FROM pg_catalog.pg_subscription AS subscription
		          WHERE subscription.subdbid = (
		              SELECT database.oid
		                FROM pg_catalog.pg_database AS database
		               WHERE database.datname =
		                     pg_catalog.current_database()
		          )
		     ),
		     NOT EXISTS (
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
		          WHERE namespace.nspname IN (
		                    'public',
		                    'hytch_push_vault'
		                )
		            AND privilege.privilege_type = 'CREATE'
		            AND privilege.grantee <> namespace.nspowner
		     )`,
	).Scan(
		&markerValid,
		&totalTriggerCount,
		&exactTriggerCount,
		&rejectFunctionValid,
		&activationFunctionValid,
		&rejectSource,
		&activationSource,
		&noLogicalSubscription,
		&schemaPrivilegesValid,
	); err != nil {
		return ErrStoreUnavailable
	}
	if !markerValid ||
		totalTriggerCount != 3 ||
		exactTriggerCount != 3 ||
		!rejectFunctionValid ||
		!activationFunctionValid ||
		!rejectSource.Valid ||
		!activationSource.Valid ||
		!sourceHashMatches(
			rejectSource.String,
			rejectLegacyRoutingSourceSHA256,
		) ||
		!sourceHashMatches(
			activationSource.String,
			activateLegacyRoutingSourceSHA256,
		) ||
		!noLogicalSubscription ||
		!schemaPrivilegesValid {
		return ErrLegacyRoutingBarrierInvalid
	}

	var restrictedRuntimeRole bool
	if err := s.db.QueryRowContext(
		ctx,
		`WITH protected_owners AS (
		     SELECT relation.relowner AS owner
		       FROM pg_catalog.pg_class AS relation
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = relation.relnamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		         OR (
		             namespace.nspname = 'public' AND
		             relation.relname = 'schema_migrations'
		         )
		     UNION
		     SELECT routine.proowner
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		 )
		 SELECT
		     NOT role.rolsuper AND
		     NOT role.rolreplication AND
		     NOT role.rolbypassrls AND
		     NOT role.rolcreatedb AND
		     NOT role.rolcreaterole AND
		     NOT pg_catalog.has_schema_privilege(
		         current_user,
		         'public',
		         'CREATE'
		     ) AND
		     NOT pg_catalog.has_schema_privilege(
		         current_user,
		         'hytch_push_vault',
		         'CREATE'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.legacy_routing_activation',
		         'INSERT'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.legacy_routing_activation',
		         'UPDATE'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.legacy_routing_activation',
		         'DELETE'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.legacy_routing_activation',
		         'TRUNCATE'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'public.schema_migrations',
		         'INSERT'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'public.schema_migrations',
		         'UPDATE'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'public.schema_migrations',
		         'DELETE'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'public.schema_migrations',
		         'TRUNCATE'
		     ) AND
		     NOT pg_catalog.has_function_privilege(
		         current_user,
		         'hytch_push_vault.' ||
		             'activate_legacy_routing_retirement(text)',
		         'EXECUTE'
		     ) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM protected_owners
		          WHERE pg_catalog.pg_has_role(
		              current_user,
		              protected_owners.owner,
		              'MEMBER'
		          )
		     ) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM pg_catalog.pg_roles AS powerful_role
		          WHERE powerful_role.rolname =
		                'pg_create_subscription'
		            AND pg_catalog.pg_has_role(
		                current_user,
		                powerful_role.oid,
		                'MEMBER'
		            )
		     )
		   FROM pg_catalog.pg_roles AS role
		  WHERE role.rolname = current_user`,
	).Scan(&restrictedRuntimeRole); err != nil {
		return ErrStoreUnavailable
	}
	if !restrictedRuntimeRole {
		return ErrLegacyRoutingBarrierInvalid
	}
	return nil
}

func sourceHashMatches(source, expected string) bool {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:]) == expected
}
