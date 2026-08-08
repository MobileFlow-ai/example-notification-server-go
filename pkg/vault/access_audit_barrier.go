package vault

import (
	"context"
	"database/sql"
	"errors"
)

var ErrAccessAuditBarrierInvalid = errors.New(
	"access audit append-only barrier is invalid",
)

const (
	rejectAccessAuditSourceSHA256 = "1d662281ae9e9a6b41196a545f7c831e" +
		"4b7001f1474d77b87b7b21e813038d4a"
	purgeDevelopmentAccessAuditSourceSHA256 = "adf2a0fe572646733c0b5e89636a9e65" +
		"49d86658556f263aa69709788a289eff"
	purgeProductionAccessAuditSourceSHA256 = "250ae03bdf36614becbcd9f3649de42b" +
		"ab6c70a210ee7b8e9193f3ac224c02c0"
)

// RequireAccessAuditBarrier verifies the exact database barrier protecting
// incident-access audit records and requires a restricted non-owner runtime
// role. The runtime may append and read audit records and invoke only the
// environment-scoped expiry purge; it may not mutate or directly delete rows.
func (s *Store) RequireAccessAuditBarrier(ctx context.Context) error {
	if s == nil || s.db == nil ||
		(s.environmentID != environmentDevelopment &&
			s.environmentID != environmentProduction) {
		return ErrStoreUnavailable
	}

	var (
		relationValid          bool
		indexesValid           bool
		constraintsValid       bool
		totalTriggerCount      int
		exactTriggerCount      int
		rejectFunctionValid    bool
		purgeFunctionsValid    bool
		rejectSource           sql.NullString
		purgeDevelopmentSource sql.NullString
		purgeProductionSource  sql.NullString
		noEnabledEventHooks    bool
		schemaPrivilegesSafe   bool
	)
	if err := s.db.QueryRowContext(
		ctx,
		`WITH audit_relation AS (
		     SELECT relation.*
		       FROM pg_catalog.pg_class AS relation
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = relation.relnamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND relation.relname = 'access_audit'
		 ),
		 reject_routine AS (
		     SELECT routine.*
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND routine.proname = 'reject_access_audit_mutation'
		        AND routine.pronargs = 0
		 ),
		 development_purge_routine AS (
		     SELECT routine.*
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND routine.proname =
		            'purge_expired_access_audit_development'
		        AND routine.pronargs = 0
		 ),
		 production_purge_routine AS (
		     SELECT routine.*
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND routine.proname =
		            'purge_expired_access_audit_production'
		        AND routine.pronargs = 0
		 ),
		 expected_column (
		     column_name,
		     column_number,
		     column_type
		 ) AS (
		     VALUES
		         (
		             'event_id',
		             1::pg_catalog.int2,
		             'pg_catalog.bytea'::pg_catalog.regtype
		         ),
		         (
		             'request_id',
		             2::pg_catalog.int2,
		             'pg_catalog.bytea'::pg_catalog.regtype
		         ),
		         (
		             'environment',
		             3::pg_catalog.int2,
		             'pg_catalog.int2'::pg_catalog.regtype
		         ),
		         (
		             'actor',
		             4::pg_catalog.int2,
		             'pg_catalog.text'::pg_catalog.regtype
		         ),
		         (
		             'purpose',
		             5::pg_catalog.int2,
		             'pg_catalog.int2'::pg_catalog.regtype
		         ),
		         (
		             'data_class',
		             6::pg_catalog.int2,
		             'pg_catalog.int2'::pg_catalog.regtype
		         ),
		         (
		             'coarse_event_hour',
		             7::pg_catalog.int2,
		             'pg_catalog.timestamptz'::pg_catalog.regtype
		         ),
		         (
		             'action',
		             8::pg_catalog.int2,
		             'pg_catalog.int2'::pg_catalog.regtype
		         ),
		         (
		             'result_count_bucket',
		             9::pg_catalog.int2,
		             'pg_catalog.int2'::pg_catalog.regtype
		         ),
		         (
		             'expires_on',
		             10::pg_catalog.int2,
		             'pg_catalog.date'::pg_catalog.regtype
		         )
		 ),
		 expected_trigger (trigger_name, trigger_type) AS (
		     VALUES
		         (
		             'hytch_access_audit_update_guard',
		             18::pg_catalog.int2
		         ),
		         (
		             'hytch_access_audit_delete_guard',
		             10::pg_catalog.int2
		         ),
		         (
		             'hytch_access_audit_truncate_guard',
		             34::pg_catalog.int2
		         )
		 ),
		 expected_check (
		     constraint_name,
		     column_numbers,
		     constraint_expression
		 ) AS (
		     VALUES
		         (
		             'access_audit_event_id_check',
		             ARRAY[1]::pg_catalog.int2[],
		             'octet_length(event_id) = 16'
		         ),
		         (
		             'access_audit_environment_check',
		             ARRAY[3]::pg_catalog.int2[],
		             'environment = ANY (ARRAY[1, 2])'
		         ),
		         (
		             'access_audit_coarse_event_hour_check',
		             ARRAY[7]::pg_catalog.int2[],
		             'date_trunc(''hour''::text, ' ||
		                 'timezone(''UTC''::text, coarse_event_hour)) = ' ||
		                 'timezone(''UTC''::text, coarse_event_hour)'
		         ),
		         (
		             'access_audit_check',
		             ARRAY[10, 7]::pg_catalog.int2[],
		             'expires_on <= ' ||
		                 '(timezone(''UTC''::text, coarse_event_hour)' ||
		                 '::date + 180)'
		         )
		 )
		 SELECT
		     COALESCE((
		         SELECT
			             audit.relkind = 'r' AND
			             audit.relpersistence = 'p' AND
			             NOT audit.relispartition AND
			             NOT audit.relhassubclass AND
			             NOT audit.relrowsecurity AND
		             NOT audit.relforcerowsecurity AND
		             audit.relchecks = 4 AND
			             audit.relowner = reject.proowner AND
			             audit.relowner =
			                 development_purge.proowner AND
			             audit.relowner =
			                 production_purge.proowner AND
		             (
		                 SELECT pg_catalog.count(*) = 10
		                   FROM pg_catalog.pg_attribute AS attribute
		                  WHERE attribute.attrelid = audit.oid
		                    AND attribute.attnum > 0
		                    AND NOT attribute.attisdropped
		             ) AND
		             (
		                 SELECT pg_catalog.count(*) = 10 AND
		                        COALESCE(pg_catalog.bool_and(
			                            attribute.attnum =
			                                expected.column_number AND
			                            attribute.atttypid =
			                                expected.column_type AND
			                            attribute.attnotnull AND
			                            attribute.attacl IS NULL AND
			                            NOT attribute.atthasdef AND
		                            attribute.attidentity = '' AND
		                            attribute.attgenerated = ''
		                        ), FALSE)
		                   FROM pg_catalog.pg_attribute AS attribute
		                   JOIN expected_column AS expected
		                     ON expected.column_name =
		                        attribute.attname
		                  WHERE attribute.attrelid = audit.oid
		                    AND attribute.attnum > 0
		                    AND NOT attribute.attisdropped
		             ) AND
			             NOT EXISTS (
			                 SELECT 1
			                   FROM pg_catalog.pg_policy AS policy
			                  WHERE policy.polrelid = audit.oid
			             ) AND
			             NOT EXISTS (
			                 SELECT 1
			                   FROM pg_catalog.pg_inherits AS inheritance
			                  WHERE inheritance.inhparent = audit.oid
			                     OR inheritance.inhrelid = audit.oid
			             ) AND
			             NOT EXISTS (
		                 SELECT 1
		                   FROM pg_catalog.pg_rewrite AS rewrite_rule
		                  WHERE rewrite_rule.ev_class = audit.oid
		             ) AND
		             NOT EXISTS (
		                 SELECT 1
		                   FROM pg_catalog.aclexplode(
		                       COALESCE(
		                           audit.relacl,
		                           pg_catalog.acldefault(
		                               'r',
		                               audit.relowner
		                           )
		                       )
		                   ) AS privilege
		                  WHERE privilege.grantee = 0
		             )
			           FROM audit_relation AS audit
			           JOIN reject_routine AS reject ON TRUE
			           JOIN development_purge_routine AS development_purge
			             ON TRUE
			           JOIN production_purge_routine AS production_purge
			             ON TRUE
		     ), FALSE),
		     COALESCE((
		         SELECT
		             pg_catalog.count(*) = 2 AND
		             pg_catalog.count(*) FILTER (
		                 WHERE index_relation.relname =
		                       'access_audit_pkey'
		                   AND access_method.amname = 'btree'
		                   AND index_record.indisprimary
		                   AND index_record.indisunique
		                   AND index_record.indisvalid
		                   AND index_record.indisready
		                   AND index_record.indislive
		                   AND index_record.indimmediate
		                   AND NOT index_record.indisexclusion
		                   AND index_record.indnkeyatts = 1
		                   AND index_record.indnatts = 1
		                   AND index_record.indkey::pg_catalog.text = '1'
		                   AND index_record.indexprs IS NULL
		                   AND index_record.indpred IS NULL
		             ) = 1 AND
		             pg_catalog.count(*) FILTER (
		                 WHERE index_relation.relname =
		                       'access_audit_expiry_idx'
		                   AND access_method.amname = 'btree'
		                   AND NOT index_record.indisprimary
		                   AND NOT index_record.indisunique
		                   AND index_record.indisvalid
		                   AND index_record.indisready
		                   AND index_record.indislive
		                   AND index_record.indimmediate
		                   AND NOT index_record.indisexclusion
		                   AND index_record.indnkeyatts = 2
		                   AND index_record.indnatts = 2
		                   AND index_record.indkey::pg_catalog.text =
		                       '3 10'
		                   AND index_record.indexprs IS NULL
		                   AND index_record.indpred IS NULL
		             ) = 1
		           FROM pg_catalog.pg_index AS index_record
		           JOIN audit_relation AS audit
		             ON audit.oid = index_record.indrelid
		           JOIN pg_catalog.pg_class AS index_relation
		             ON index_relation.oid = index_record.indexrelid
		           JOIN pg_catalog.pg_am AS access_method
		             ON access_method.oid = index_relation.relam
		     ), FALSE),
		     COALESCE((
		         SELECT
			             pg_catalog.count(*) = 6 AND
			             pg_catalog.count(*) FILTER (
			                 WHERE constraint_record.conname =
			                       'access_audit_pkey'
			                   AND constraint_record.contype = 'p'
			                   AND constraint_record.conkey =
			                       ARRAY[1]::pg_catalog.int2[]
			             ) = 1 AND
			             pg_catalog.count(*) FILTER (
			                 WHERE constraint_record.conname =
			                       'access_audit_request_id_environment_fkey'
			                   AND constraint_record.contype = 'f'
			                   AND constraint_record.conkey =
			                       ARRAY[2, 3]::pg_catalog.int2[]
		                   AND constraint_record.confrelid =
		                       'hytch_push_vault.access_requests'
		                           ::pg_catalog.regclass
		                   AND constraint_record.confkey =
		                       ARRAY[1, 2]::pg_catalog.int2[]
		                   AND constraint_record.confmatchtype = 's'
		                   AND constraint_record.confupdtype = 'a'
		                   AND constraint_record.confdeltype = 'a'
		             ) = 1 AND
			             pg_catalog.count(*) FILTER (
			                 WHERE constraint_record.contype = 'c'
			                   AND EXISTS (
			                       SELECT 1
			                         FROM expected_check AS expected
			                        WHERE expected.constraint_name =
			                              constraint_record.conname
			                          AND expected.column_numbers =
			                              constraint_record.conkey
			                          AND expected.constraint_expression =
			                              pg_catalog.pg_get_expr(
			                                  constraint_record.conbin,
			                                  constraint_record.conrelid,
			                                  TRUE
			                              )
			                   )
			             ) = 4 AND
			             COALESCE(pg_catalog.bool_and(
			                 constraint_record.convalidated AND
			                 NOT constraint_record.condeferrable AND
			                 NOT constraint_record.condeferred AND
			                 constraint_record.conislocal AND
			                 constraint_record.coninhcount = 0 AND
			                 (
			                     (
			                         constraint_record.contype IN ('p', 'f') AND
			                         constraint_record.connoinherit
			                     ) OR (
			                         constraint_record.contype = 'c' AND
			                         NOT constraint_record.connoinherit
			                     )
			                 )
			             ), FALSE)
		           FROM pg_catalog.pg_constraint AS constraint_record
		           JOIN audit_relation AS audit
		             ON audit.oid = constraint_record.conrelid
		     ), FALSE),
		     (
		         SELECT pg_catalog.count(*)
		           FROM pg_catalog.pg_trigger AS trigger
		           JOIN audit_relation AS audit
		             ON audit.oid = trigger.tgrelid
		          WHERE NOT trigger.tgisinternal
		     ),
		     (
		         SELECT pg_catalog.count(*)
		           FROM expected_trigger AS expected
		           JOIN audit_relation AS audit ON TRUE
		           JOIN pg_catalog.pg_trigger AS trigger
		             ON trigger.tgrelid = audit.oid
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
		            AND (
		                SELECT pg_catalog.count(*) = 1
		                  FROM pg_catalog.pg_proc AS named_routine
		                  JOIN pg_catalog.pg_namespace AS namespace
		                    ON namespace.oid =
		                       named_routine.pronamespace
		                 WHERE namespace.nspname =
		                       'hytch_push_vault'
		                   AND named_routine.proname =
		                       'reject_access_audit_mutation'
		            )
			     ),
			     (
			         SELECT
			             pg_catalog.count(*) = 2 AND
			             COALESCE(pg_catalog.bool_and(
			                 routine.prokind = 'f' AND
			                 routine.prorettype =
			                     'pg_catalog.int8'::pg_catalog.regtype AND
			                 routine.proargtypes =
			                     ''::pg_catalog.oidvector AND
			                 routine.prosecdef AND
			                 NOT routine.proleakproof AND
			                 NOT routine.proisstrict AND
			                 NOT routine.proretset AND
			                 routine.provolatile = 'v' AND
			                 routine.proparallel = 'u' AND
			                 routine.proconfig = ARRAY[
			                     'search_path=pg_catalog'
			                 ]::pg_catalog.text[] AND
			                 language.lanname = 'plpgsql' AND
			                 NOT EXISTS (
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
			                      WHERE privilege.privilege_type =
			                            'EXECUTE'
			                        AND privilege.grantee = 0
			                 )
			             ), FALSE) AND
			             (
			                 SELECT pg_catalog.count(*) = 2
			                   FROM pg_catalog.pg_proc AS named_routine
			                   JOIN pg_catalog.pg_namespace AS namespace
			                     ON namespace.oid =
			                        named_routine.pronamespace
			                  WHERE namespace.nspname =
			                        'hytch_push_vault'
			                    AND named_routine.proname LIKE
			                        'purge_expired_access_audit%'
			             )
			           FROM (
			               SELECT development.*
			                 FROM development_purge_routine AS development
			               UNION ALL
			               SELECT production.*
			                 FROM production_purge_routine AS production
			           ) AS routine
			           JOIN pg_catalog.pg_language AS language
			             ON language.oid = routine.prolang
			     ),
			     (
			         SELECT pg_catalog.max(routine.prosrc)
			           FROM reject_routine AS routine
			     ),
			     (
			         SELECT pg_catalog.max(routine.prosrc)
			           FROM development_purge_routine AS routine
			     ),
			     (
			         SELECT pg_catalog.max(routine.prosrc)
			           FROM production_purge_routine AS routine
			     ),
		     NOT EXISTS (
		         SELECT 1
		           FROM pg_catalog.pg_event_trigger AS event_trigger
		          WHERE event_trigger.evtenabled <> 'D'
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
		          WHERE namespace.nspname = 'hytch_push_vault'
		            AND privilege.privilege_type = 'CREATE'
		            AND privilege.grantee <> namespace.nspowner
		     )`,
	).Scan(
		&relationValid,
		&indexesValid,
		&constraintsValid,
		&totalTriggerCount,
		&exactTriggerCount,
		&rejectFunctionValid,
		&purgeFunctionsValid,
		&rejectSource,
		&purgeDevelopmentSource,
		&purgeProductionSource,
		&noEnabledEventHooks,
		&schemaPrivilegesSafe,
	); err != nil {
		return ErrStoreUnavailable
	}
	if !relationValid ||
		!indexesValid ||
		!constraintsValid ||
		totalTriggerCount != 3 ||
		exactTriggerCount != 3 ||
		!rejectFunctionValid ||
		!purgeFunctionsValid ||
		!rejectSource.Valid ||
		!purgeDevelopmentSource.Valid ||
		!purgeProductionSource.Valid ||
		!sourceHashMatches(
			rejectSource.String,
			rejectAccessAuditSourceSHA256,
		) ||
		!sourceHashMatches(
			purgeDevelopmentSource.String,
			purgeDevelopmentAccessAuditSourceSHA256,
		) ||
		!sourceHashMatches(
			purgeProductionSource.String,
			purgeProductionAccessAuditSourceSHA256,
		) ||
		!noEnabledEventHooks ||
		!schemaPrivilegesSafe {
		return ErrAccessAuditBarrierInvalid
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
		        AND relation.relname = 'access_audit'
		     UNION
		     SELECT routine.proowner
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
			        AND routine.proname IN (
			            'reject_access_audit_mutation',
			            'purge_expired_access_audit_development',
			            'purge_expired_access_audit_production'
		        )
		 )
		 SELECT
		     NOT role.rolsuper AND
		     NOT role.rolreplication AND
		     NOT role.rolbypassrls AND
		     NOT role.rolcreatedb AND
		     NOT role.rolcreaterole AND
		     pg_catalog.has_schema_privilege(
		         current_user,
		         'hytch_push_vault',
		         'USAGE'
		     ) AND
		     NOT pg_catalog.has_schema_privilege(
		         current_user,
		         'hytch_push_vault',
		         'CREATE'
		     ) AND
		     pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.access_audit',
		         'SELECT'
		     ) AND
		     pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.access_audit',
		         'INSERT'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.access_audit',
		         'SELECT WITH GRANT OPTION'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.access_audit',
		         'INSERT WITH GRANT OPTION'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.access_audit',
		         'UPDATE'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.access_audit',
		         'DELETE'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.access_audit',
		         'TRUNCATE'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.access_audit',
		         'REFERENCES'
		     ) AND
		     NOT pg_catalog.has_table_privilege(
		         current_user,
		         'hytch_push_vault.access_audit',
		         'TRIGGER'
		     ) AND
		     NOT pg_catalog.has_function_privilege(
		         current_user,
		         'hytch_push_vault.' ||
		             'reject_access_audit_mutation()',
		         'EXECUTE'
		     ) AND
			     (
			         (
			             $1 = 1 AND
			             pg_catalog.has_function_privilege(
			                 current_user,
			                 'hytch_push_vault.' ||
			                     'purge_expired_access_audit_' ||
			                     'development()',
			                 'EXECUTE'
			             ) AND
			             NOT pg_catalog.has_function_privilege(
			                 current_user,
			                 'hytch_push_vault.' ||
			                     'purge_expired_access_audit_' ||
			                     'development()',
			                 'EXECUTE WITH GRANT OPTION'
			             ) AND
			             NOT pg_catalog.has_function_privilege(
			                 current_user,
			                 'hytch_push_vault.' ||
			                     'purge_expired_access_audit_' ||
			                     'production()',
			                 'EXECUTE'
			             )
			         ) OR (
			             $1 = 2 AND
			             pg_catalog.has_function_privilege(
			                 current_user,
			                 'hytch_push_vault.' ||
			                     'purge_expired_access_audit_' ||
			                     'production()',
			                 'EXECUTE'
			             ) AND
			             NOT pg_catalog.has_function_privilege(
			                 current_user,
			                 'hytch_push_vault.' ||
			                     'purge_expired_access_audit_' ||
			                     'production()',
			                 'EXECUTE WITH GRANT OPTION'
			             ) AND
			             NOT pg_catalog.has_function_privilege(
			                 current_user,
			                 'hytch_push_vault.' ||
			                     'purge_expired_access_audit_' ||
			                     'development()',
			                 'EXECUTE'
			             )
			         )
			     ) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM protected_owners
		          WHERE pg_catalog.pg_has_role(
		              current_user,
		              protected_owners.owner,
		              'MEMBER'
		          )
		     )
		   FROM pg_catalog.pg_roles AS role
			  WHERE role.rolname = current_user`,
		s.environmentID,
	).Scan(&restrictedRuntimeRole); err != nil {
		return ErrStoreUnavailable
	}
	if !restrictedRuntimeRole {
		return ErrAccessAuditBarrierInvalid
	}
	return nil
}
