package db

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a3trust"
)

const a3WitnessLockClass = 0x413357

const rejectA3WitnessSourceSHA256 = "089c9f0d36f8167ca75a477788755cce" +
	"7c0ec861f805a7d17b0dc9410244821c"

var ErrA3WitnessBarrierInvalid = errors.New(
	"A3 witness durable-state barrier is invalid",
)

type A3WitnessStore struct{ db *sql.DB }

func NewA3WitnessStore(db *sql.DB) *A3WitnessStore {
	return &A3WitnessStore{db: db}
}

// RequireActivationBarrier proves that the witness ledger still has its
// migration-pinned append-only shape and that the current connection is a
// least-privilege runtime role. It is a read-only gate and must succeed before
// the witness HTTP route is mounted.
func (store *A3WitnessStore) RequireActivationBarrier(ctx context.Context) error {
	if store == nil || store.db == nil || ctx == nil || ctx.Err() != nil {
		return a3trust.ErrUnavailable
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelSerializable,
		ReadOnly:  true,
	})
	if err != nil {
		return a3trust.ErrUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `SET LOCAL search_path = pg_catalog`); err != nil {
		return a3trust.ErrUnavailable
	}

	var (
		catalogValid         bool
		rejectFunctionSource sql.NullString
	)
	if err = tx.QueryRowContext(
		ctx,
		`WITH witness_relation AS (
		     SELECT relation.*, namespace.nspowner AS namespace_owner
		       FROM pg_catalog.pg_class AS relation
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = relation.relnamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND relation.relname = 'a3_directory_witness_heads'
		 ),
		 reject_routine AS (
		     SELECT routine.*
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND routine.proname = 'reject_a3_witness_mutation'
		        AND routine.pronargs = 0
		 ),
		 server_version AS (
		     SELECT pg_catalog.current_setting(
		                'server_version_num'
		            )::pg_catalog.int4 AS number
		 ),
		 expected_column (
		     column_number, column_name, column_type, has_default,
		     default_expression
		 ) AS (
		     VALUES
		         (1::pg_catalog.int2, 'environment',
		          'pg_catalog.int2'::pg_catalog.regtype, FALSE, NULL),
		         (2::pg_catalog.int2, 'tree_size',
		          'pg_catalog.int8'::pg_catalog.regtype, FALSE, NULL),
		         (3::pg_catalog.int2, 'root_hash',
		          'pg_catalog.bytea'::pg_catalog.regtype, FALSE, NULL),
		         (4::pg_catalog.int2, 'prior_tree_size',
		          'pg_catalog.int8'::pg_catalog.regtype, FALSE, NULL),
		         (5::pg_catalog.int2, 'prior_root_hash',
		          'pg_catalog.bytea'::pg_catalog.regtype, FALSE, NULL),
		         (6::pg_catalog.int2, 'timestamp_ms',
		          'pg_catalog.int8'::pg_catalog.regtype, FALSE, NULL),
		         (7::pg_catalog.int2, 'canonical_head',
		          'pg_catalog.bytea'::pg_catalog.regtype, FALSE, NULL),
		         (8::pg_catalog.int2, 'consistency_proof',
		          'pg_catalog.bytea'::pg_catalog.regtype, FALSE, NULL),
		         (9::pg_catalog.int2, 'witness_key_id',
		          'pg_catalog.text'::pg_catalog.regtype, FALSE, NULL),
		         (10::pg_catalog.int2, 'witness_signature',
		          'pg_catalog.bytea'::pg_catalog.regtype, FALSE, NULL),
		         (11::pg_catalog.int2, 'accepted_at',
		          'pg_catalog.timestamptz'::pg_catalog.regtype, TRUE,
		          'clock_timestamp()')
		 ),
		 expected_trigger (trigger_name, trigger_type) AS (
		     VALUES
		         ('hytch_a3_witness_update_guard', 18::pg_catalog.int2),
		         ('hytch_a3_witness_delete_guard', 10::pg_catalog.int2),
		         ('hytch_a3_witness_truncate_guard', 34::pg_catalog.int2)
		 ),
		 expected_not_null (
		     constraint_name, column_number, constraint_definition
		 ) AS (
		     VALUES
		         ('a3_directory_witness_heads_environment_not_null',
		          1::pg_catalog.int2, 'NOT NULL environment'),
		         ('a3_directory_witness_heads_tree_size_not_null',
		          2::pg_catalog.int2, 'NOT NULL tree_size'),
		         ('a3_directory_witness_heads_root_hash_not_null',
		          3::pg_catalog.int2, 'NOT NULL root_hash'),
		         ('a3_directory_witness_heads_prior_tree_size_not_null',
		          4::pg_catalog.int2, 'NOT NULL prior_tree_size'),
		         ('a3_directory_witness_heads_prior_root_hash_not_null',
		          5::pg_catalog.int2, 'NOT NULL prior_root_hash'),
		         ('a3_directory_witness_heads_timestamp_ms_not_null',
		          6::pg_catalog.int2, 'NOT NULL timestamp_ms'),
		         ('a3_directory_witness_heads_canonical_head_not_null',
		          7::pg_catalog.int2, 'NOT NULL canonical_head'),
		         ('a3_directory_witness_heads_consistency_proof_not_null',
		          8::pg_catalog.int2, 'NOT NULL consistency_proof'),
		         ('a3_directory_witness_heads_witness_key_id_not_null',
		          9::pg_catalog.int2, 'NOT NULL witness_key_id'),
		         ('a3_directory_witness_heads_witness_signature_not_null',
		          10::pg_catalog.int2, 'NOT NULL witness_signature'),
		         ('a3_directory_witness_heads_accepted_at_not_null',
		          11::pg_catalog.int2, 'NOT NULL accepted_at')
		 ),
		 expected_check (
		     constraint_name,
		     column_numbers,
		     constraint_definition_pg13,
		     constraint_definition_pg18
		 ) AS (
		     VALUES
		         ('a3_witness_environment_check',
		          ARRAY[1]::pg_catalog.int2[],
		          'CHECK ((environment = ANY (ARRAY[1, 2])))',
		          'CHECK ((environment = ANY (ARRAY[1, 2])))'),
		         ('a3_witness_tree_size_check',
		          ARRAY[2]::pg_catalog.int2[],
		          'CHECK (((tree_size >= 1) AND (tree_size <= ' ||
		              '''9007199254740991''::bigint)))',
		          'CHECK (((tree_size >= 1) AND (tree_size <= ' ||
		              '''9007199254740991''::bigint)))'),
		         ('a3_witness_root_hash_check',
		          ARRAY[3]::pg_catalog.int2[],
		          'CHECK ((octet_length(root_hash) = 32))',
		          'CHECK ((octet_length(root_hash) = 32))'),
		         ('a3_witness_prior_tree_size_check',
		          ARRAY[4]::pg_catalog.int2[],
		          'CHECK (((prior_tree_size >= 0) AND ' ||
		              '(prior_tree_size <= ' ||
		              '''9007199254740991''::bigint)))',
		          'CHECK (((prior_tree_size >= 0) AND ' ||
		              '(prior_tree_size <= ' ||
		              '''9007199254740991''::bigint)))'),
		         ('a3_witness_prior_root_hash_check',
		          ARRAY[5]::pg_catalog.int2[],
		          'CHECK ((octet_length(prior_root_hash) = 32))',
		          'CHECK ((octet_length(prior_root_hash) = 32))'),
		         ('a3_witness_timestamp_ms_check',
		          ARRAY[6]::pg_catalog.int2[],
		          'CHECK (((timestamp_ms >= 0) AND (timestamp_ms <= ' ||
		              '''9007199254740991''::bigint)))',
		          'CHECK (((timestamp_ms >= 0) AND (timestamp_ms <= ' ||
		              '''9007199254740991''::bigint)))'),
		         ('a3_witness_canonical_head_check',
		          ARRAY[7]::pg_catalog.int2[],
		          'CHECK (((octet_length(canonical_head) >= 1) AND ' ||
		              '(octet_length(canonical_head) <= 4096)))',
		          'CHECK (((octet_length(canonical_head) >= 1) AND ' ||
		              '(octet_length(canonical_head) <= 4096)))'),
		         ('a3_witness_consistency_proof_check',
		          ARRAY[8]::pg_catalog.int2[],
		          'CHECK (((octet_length(consistency_proof) <= 2048) AND ' ||
		              '((octet_length(consistency_proof) % 32) = 0)))',
		          'CHECK (((octet_length(consistency_proof) <= 2048) AND ' ||
		              '((octet_length(consistency_proof) % 32) = 0)))'),
		         ('a3_witness_key_id_check',
		          ARRAY[9]::pg_catalog.int2[],
		          'CHECK (((length(witness_key_id) = 79) AND ' ||
		              '(witness_key_id ~ ' ||
		              '''^ed25519-sha256:[0-9a-f]{64}$''::text)))',
		          'CHECK (((length(witness_key_id) = 79) AND ' ||
		              '(witness_key_id ~ ' ||
		              '''^ed25519-sha256:[0-9a-f]{64}$''::text)))'),
		         ('a3_witness_signature_check',
		          ARRAY[10]::pg_catalog.int2[],
		          'CHECK ((octet_length(witness_signature) = 64))',
		          'CHECK ((octet_length(witness_signature) = 64))'),
		         ('a3_witness_predecessor_check',
		          ARRAY[4, 2]::pg_catalog.int2[],
		          'CHECK ((prior_tree_size < tree_size))',
		          'CHECK ((prior_tree_size < tree_size))')
		 )
		 SELECT
		     COALESCE((
		         SELECT
		             relation.relkind = 'r' AND
		             relation.relpersistence = 'p' AND
		             NOT relation.relispartition AND
		             NOT relation.relhassubclass AND
		             NOT relation.relrowsecurity AND
		             NOT relation.relforcerowsecurity AND
		             NOT relation.relhasrules AND
		             relation.relhastriggers AND
		             relation.relchecks = 11 AND
		             relation.namespace_owner = relation.relowner AND
		             relation.relowner = routine.proowner AND
		             NOT EXISTS (
		                 SELECT 1
		                   FROM pg_catalog.pg_inherits AS inheritance
		                  WHERE inheritance.inhrelid = relation.oid OR
		                        inheritance.inhparent = relation.oid
		             ) AND
		             (
		                 SELECT pg_catalog.count(*) = 11
		                   FROM pg_catalog.pg_attribute AS actual_attribute
		                  WHERE actual_attribute.attrelid = relation.oid
		                    AND actual_attribute.attnum > 0
		                    AND NOT actual_attribute.attisdropped
		             ) AND
		             (
		                 SELECT pg_catalog.count(*) = 11 AND
		                        COALESCE(pg_catalog.bool_and(
		                            attribute.attname = expected.column_name AND
		                            attribute.atttypid = expected.column_type AND
		                            attribute.attnotnull AND
		                            attribute.attidentity = '' AND
		                            attribute.attgenerated = '' AND
		                            attribute.attacl IS NULL AND
		                            attribute.attoptions IS NULL AND
		                            attribute.atthasdef = expected.has_default AND
		                            (
		                                (NOT expected.has_default AND
		                                 default_record.oid IS NULL) OR
		                                (expected.has_default AND
		                                 pg_catalog.pg_get_expr(
		                                     default_record.adbin,
		                                     default_record.adrelid
		                                 ) = expected.default_expression)
		                            )
		                        ), FALSE)
		                   FROM expected_column AS expected
		                   JOIN pg_catalog.pg_attribute AS attribute
		                     ON attribute.attrelid = relation.oid
		                    AND attribute.attnum = expected.column_number
		                    AND NOT attribute.attisdropped
		                   LEFT JOIN pg_catalog.pg_attrdef AS default_record
		                     ON default_record.adrelid = relation.oid
		                    AND default_record.adnum = attribute.attnum
		             ) AND
		             COALESCE((
		                 SELECT
		                     (
		                         (
		                             version.number >= 130000 AND
		                             version.number < 140000 AND
		                             pg_catalog.count(*) = 12 AND
		                             pg_catalog.count(*) FILTER (
		                                 WHERE constraint_record.contype = 'n'
		                             ) = 0
		                         ) OR (
		                             version.number >= 180000 AND
		                             version.number < 190000 AND
		                             pg_catalog.count(*) = 23 AND
		                             pg_catalog.count(*) FILTER (
		                                 WHERE constraint_record.contype = 'n' AND
		                                       constraint_record.convalidated AND
		                                       COALESCE((
		                                           pg_catalog.to_jsonb(
		                                               constraint_record
		                                           )->>'conenforced'
		                                       )::pg_catalog.bool, FALSE) AND
		                                       NOT COALESCE((
		                                           pg_catalog.to_jsonb(
		                                               constraint_record
		                                           )->>'conperiod'
		                                       )::pg_catalog.bool, TRUE) AND
		                                       NOT constraint_record.condeferrable AND
		                                       NOT constraint_record.condeferred AND
		                                       constraint_record.conislocal AND
		                                       constraint_record.coninhcount = 0 AND
		                                       NOT constraint_record.connoinherit AND
		                                       constraint_record.conparentid = 0 AND
		                                       constraint_record.contypid = 0 AND
		                                       constraint_record.conindid = 0 AND
		                                       constraint_record.confrelid = 0 AND
		                                       constraint_record.confkey IS NULL AND
		                                       constraint_record.confmatchtype = ' ' AND
		                                       constraint_record.confupdtype = ' ' AND
		                                       constraint_record.confdeltype = ' ' AND
		                                       constraint_record.conbin IS NULL AND
		                                       EXISTS (
		                                           SELECT 1
		                                             FROM expected_not_null AS expected
		                                            WHERE expected.constraint_name =
		                                                  constraint_record.conname
		                                              AND constraint_record.conkey =
		                                                  ARRAY[expected.column_number]
		                                                      ::pg_catalog.int2[]
		                                              AND expected.constraint_definition =
		                                                  pg_catalog.pg_get_constraintdef(
		                                                      constraint_record.oid,
		                                                      FALSE
		                                                  )
		                                       )
		                             ) = 11
		                         )
		                     ) AND
		                     pg_catalog.count(*) FILTER (
		                         WHERE constraint_record.contype IN ('p', 'c')
		                     ) = 12 AND
		                     pg_catalog.count(*) FILTER (
		                         WHERE constraint_record.contype = 'p' AND
		                               constraint_record.conname =
		                                   'a3_directory_witness_heads_pkey' AND
		                               constraint_record.conkey =
		                                   ARRAY[1, 2]::pg_catalog.int2[] AND
		                               pg_catalog.pg_get_constraintdef(
		                                   constraint_record.oid,
		                                   FALSE
		                               ) =
		                                   'PRIMARY KEY (environment, tree_size)'
		                     ) = 1 AND
		                     pg_catalog.count(*) FILTER (
		                         WHERE constraint_record.contype = 'c' AND
		                               EXISTS (
		                                   SELECT 1
		                                     FROM expected_check AS expected
		                                    WHERE expected.constraint_name =
		                                          constraint_record.conname
		                                      AND expected.column_numbers =
		                                          constraint_record.conkey
		                                      AND (
		                                          (
		                                              version.number >= 130000 AND
		                                              version.number < 140000 AND
		                                              expected.constraint_definition_pg13 =
		                                                  pg_catalog.pg_get_constraintdef(
		                                                      constraint_record.oid,
		                                                      FALSE
		                                                  )
		                                          ) OR (
		                                              version.number >= 180000 AND
		                                              version.number < 190000 AND
		                                              expected.constraint_definition_pg18 =
		                                                  pg_catalog.pg_get_constraintdef(
		                                                      constraint_record.oid,
		                                                      FALSE
		                                                  )
		                                          )
		                                      )
		                               )
		                     ) = 11 AND
		                     COALESCE(pg_catalog.bool_and(
		                         constraint_record.convalidated AND
		                         NOT constraint_record.condeferrable AND
		                         NOT constraint_record.condeferred AND
		                         constraint_record.conislocal AND
		                         constraint_record.coninhcount = 0 AND
		                         constraint_record.conparentid = 0 AND
		                         constraint_record.contypid = 0 AND
		                         constraint_record.confrelid = 0 AND
		                         constraint_record.confkey IS NULL AND
		                         constraint_record.confmatchtype = ' ' AND
		                         constraint_record.confupdtype = ' ' AND
		                         constraint_record.confdeltype = ' ' AND
		                         (
		                             version.number < 180000 OR (
		                                 COALESCE((
		                                     pg_catalog.to_jsonb(
		                                         constraint_record
		                                     )->>'conenforced'
		                                 )::pg_catalog.bool, FALSE) AND
		                                 NOT COALESCE((
		                                     pg_catalog.to_jsonb(
		                                         constraint_record
		                                     )->>'conperiod'
		                                 )::pg_catalog.bool, TRUE)
		                             )
		                         ) AND
		                         (
		                             (
		                                 constraint_record.contype = 'p' AND
		                                 constraint_record.connoinherit AND
		                                 constraint_record.conindid <> 0 AND
		                                 constraint_record.conbin IS NULL
		                             ) OR (
		                                 constraint_record.contype = 'c' AND
		                                 NOT constraint_record.connoinherit AND
		                                 constraint_record.conindid = 0 AND
		                                 constraint_record.conbin IS NOT NULL
		                             )
		                         )
		                     ) FILTER (
		                         WHERE constraint_record.contype IN ('p', 'c')
		                     ), FALSE)
		                   FROM pg_catalog.pg_constraint AS constraint_record
		                   CROSS JOIN server_version AS version
		                  WHERE constraint_record.conrelid = relation.oid
		                  GROUP BY version.number
		             ), FALSE) AND
		             (
		                 SELECT pg_catalog.count(*) = 1 AND
		                        COALESCE(pg_catalog.bool_and(
		                            index_relation.relname =
		                                'a3_directory_witness_heads_pkey' AND
		                            index_relation.relnamespace =
		                                relation.relnamespace AND
		                            index_relation.relowner = relation.relowner AND
		                            index_relation.relkind = 'i' AND
		                            index_relation.relpersistence = 'p' AND
		                            NOT index_relation.relispartition AND
		                            NOT index_relation.relhassubclass AND
		                            NOT index_relation.relhasrules AND
		                            NOT index_relation.relhastriggers AND
		                            NOT index_relation.relrowsecurity AND
		                            NOT index_relation.relforcerowsecurity AND
		                            index_relation.relchecks = 0 AND
		                            index_relation.relacl IS NULL AND
		                            index_relation.reloptions IS NULL AND
		                            index_relation.relpartbound IS NULL AND
		                            access_method.amname = 'btree' AND
		                            index_record.indisprimary AND
		                            index_record.indisunique AND
		                            index_record.indisvalid AND
		                            index_record.indisready AND
		                            index_record.indislive AND
		                            index_record.indimmediate AND
		                            NOT index_record.indisexclusion AND
		                            NOT index_record.indisclustered AND
		                            NOT index_record.indisreplident AND
		                            NOT index_record.indcheckxmin AND
		                            NOT COALESCE((
		                                pg_catalog.to_jsonb(index_record)->>
		                                    'indnullsnotdistinct'
		                            )::pg_catalog.bool, FALSE) AND
		                            index_record.indnkeyatts = 2 AND
		                            index_record.indnatts = 2 AND
		                            index_record.indkey::pg_catalog.text = '1 2' AND
		                            index_record.indcollation::pg_catalog.text =
		                                '0 0' AND
		                            index_record.indoption::pg_catalog.text =
		                                '0 0' AND
		                            index_record.indexprs IS NULL AND
		                            index_record.indpred IS NULL AND
		                            (
		                                SELECT pg_catalog.count(*) = 2 AND
		                                       COALESCE(pg_catalog.bool_and(
		                                           opclass_namespace.nspname =
		                                               'pg_catalog' AND
		                                           opclass.opcmethod =
		                                               access_method.oid AND
		                                           opclass.opcdefault AND
		                                           opclass.opckeytype = 0 AND
		                                           family_namespace.nspname =
		                                               'pg_catalog' AND
		                                           family.opfname =
		                                               'integer_ops' AND
		                                           family.opfmethod =
		                                               access_method.oid AND
		                                           (
		                                               (
		                                                   indexed_opclass.position = 1 AND
		                                                   opclass.opcname = 'int2_ops' AND
		                                                   opclass.opcintype =
		                                                       'pg_catalog.int2'
		                                                           ::pg_catalog.regtype
		                                               ) OR (
		                                                   indexed_opclass.position = 2 AND
		                                                   opclass.opcname = 'int8_ops' AND
		                                                   opclass.opcintype =
		                                                       'pg_catalog.int8'
		                                                           ::pg_catalog.regtype
		                                               )
		                                           )
		                                       ), FALSE)
		                                  FROM pg_catalog.unnest(
		                                           index_record.indclass::pg_catalog.oid[]
		                                       ) WITH ORDINALITY AS indexed_opclass(
		                                           oid, position
		                                       )
		                                  JOIN pg_catalog.pg_opclass AS opclass
		                                    ON opclass.oid = indexed_opclass.oid
		                                  JOIN pg_catalog.pg_namespace AS
		                                       opclass_namespace
		                                    ON opclass_namespace.oid =
		                                       opclass.opcnamespace
		                                  JOIN pg_catalog.pg_opfamily AS family
		                                    ON family.oid = opclass.opcfamily
		                                  JOIN pg_catalog.pg_namespace AS
		                                       family_namespace
		                                    ON family_namespace.oid =
		                                       family.opfnamespace
		                            ) AND
		                            (
		                                SELECT pg_catalog.count(*) = 1
		                                  FROM pg_catalog.pg_constraint AS
		                                       primary_constraint
		                                 WHERE primary_constraint.conrelid =
		                                       relation.oid
		                                   AND primary_constraint.contype = 'p'
		                                   AND primary_constraint.conindid =
		                                       index_record.indexrelid
		                            )
		                        ), FALSE)
		                   FROM pg_catalog.pg_index AS index_record
		                   JOIN pg_catalog.pg_class AS index_relation
		                     ON index_relation.oid = index_record.indexrelid
		                   JOIN pg_catalog.pg_am AS access_method
		                     ON access_method.oid = index_relation.relam
		                  WHERE index_record.indrelid = relation.oid
		             ) AND
		             NOT EXISTS (
		                 SELECT 1
		                   FROM pg_catalog.pg_policy AS policy
		                  WHERE policy.polrelid = relation.oid
		             ) AND
		             NOT EXISTS (
		                 SELECT 1
		                   FROM pg_catalog.pg_rewrite AS rewrite_rule
		                  WHERE rewrite_rule.ev_class = relation.oid
		             ) AND
		             NOT EXISTS (
		                 SELECT 1
		                   FROM pg_catalog.aclexplode(
		                       COALESCE(
		                           relation.relacl,
		                           pg_catalog.acldefault('r', relation.relowner)
		                       )
		                   ) AS privilege
		                  WHERE privilege.grantee <> relation.relowner AND (
			                      privilege.grantee <> COALESCE((
			                          SELECT role.oid
			                            FROM pg_catalog.pg_roles AS role
			                           WHERE role.rolname = session_user
		                      ), 0) OR
		                      privilege.privilege_type NOT IN (
		                          'SELECT', 'INSERT'
		                      ) OR
		                      privilege.is_grantable
		                  )
		             ) AND
		             routine.prokind = 'f' AND
		             routine.prorettype =
		                 'pg_catalog.trigger'::pg_catalog.regtype AND
		             routine.proargtypes = ''::pg_catalog.oidvector AND
		             NOT routine.prosecdef AND
		             NOT routine.proleakproof AND
		             NOT routine.proisstrict AND
		             NOT routine.proretset AND
		             routine.provolatile = 'v' AND
		             routine.proparallel = 'u' AND
		             routine.proconfig =
		                 ARRAY['search_path=pg_catalog']::pg_catalog.text[] AND
		             (
		                 SELECT language.lanname = 'plpgsql'
		                   FROM pg_catalog.pg_language AS language
		                  WHERE language.oid = routine.prolang
		             ) AND
		             NOT EXISTS (
		                 SELECT 1
		                   FROM pg_catalog.aclexplode(
		                       COALESCE(
		                           routine.proacl,
		                           pg_catalog.acldefault('f', routine.proowner)
		                       )
		                   ) AS privilege
		                  WHERE privilege.grantee <> routine.proowner
		             ) AND
		             (
		                 SELECT pg_catalog.count(*) = 3
		                   FROM pg_catalog.pg_trigger AS trigger
		                  WHERE trigger.tgrelid = relation.oid
		                    AND NOT trigger.tgisinternal
		             ) AND
		             (
		                 SELECT pg_catalog.count(*) = 3 AND
		                        COALESCE(pg_catalog.bool_and(
		                            trigger.tgenabled = 'A' AND
		                            NOT trigger.tgisinternal AND
		                            trigger.tgfoid = routine.oid AND
		                            trigger.tgtype = expected.trigger_type AND
		                            trigger.tgnargs = 0 AND
		                            pg_catalog.octet_length(trigger.tgargs) = 0 AND
		                            trigger.tgattr::pg_catalog.text = '' AND
		                            trigger.tgoldtable IS NULL AND
		                            trigger.tgnewtable IS NULL AND
		                            trigger.tgqual IS NULL AND
		                            trigger.tgconstraint = 0 AND
		                            NOT trigger.tgdeferrable AND
		                            NOT trigger.tginitdeferred
		                        ), FALSE)
		                   FROM expected_trigger AS expected
		                   JOIN pg_catalog.pg_trigger AS trigger
		                     ON trigger.tgrelid = relation.oid
		                    AND trigger.tgname = expected.trigger_name
		             )
		           FROM witness_relation AS relation
		           CROSS JOIN reject_routine AS routine
		     ), FALSE) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM pg_catalog.pg_event_trigger AS event_trigger
		          WHERE event_trigger.evtenabled <> 'D'
		     ) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM pg_catalog.pg_namespace AS namespace
		           CROSS JOIN LATERAL pg_catalog.aclexplode(
		               COALESCE(
		                   namespace.nspacl,
		                   pg_catalog.acldefault('n', namespace.nspowner)
		               )
		           ) AS privilege
		          WHERE namespace.nspname = 'hytch_push_vault' AND (
		              privilege.grantee = 0 OR (
		                  privilege.privilege_type = 'CREATE' AND
		                  privilege.grantee <> namespace.nspowner
		              )
		          )
		     ),
		     (SELECT pg_catalog.max(routine.prosrc) FROM reject_routine AS routine)`,
	).Scan(&catalogValid, &rejectFunctionSource); err != nil {
		return a3trust.ErrUnavailable
	}
	if !catalogValid || !rejectFunctionSource.Valid ||
		!a3WitnessSourceHashMatches(
			rejectFunctionSource.String,
			rejectA3WitnessSourceSHA256,
		) {
		return ErrA3WitnessBarrierInvalid
	}

	var restrictedRuntimeRole bool
	if err = tx.QueryRowContext(
		ctx,
		`WITH protected_owners AS (
		     SELECT relation.relowner AS owner
		       FROM pg_catalog.pg_class AS relation
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = relation.relnamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND relation.relname = 'a3_directory_witness_heads'
		     UNION
		     SELECT routine.proowner
		       FROM pg_catalog.pg_proc AS routine
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = routine.pronamespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		        AND routine.proname = 'reject_a3_witness_mutation'
		        AND routine.pronargs = 0
		     UNION
		     SELECT namespace.nspowner
		       FROM pg_catalog.pg_namespace AS namespace
		      WHERE namespace.nspname = 'hytch_push_vault'
		     UNION
		     SELECT relation.relowner
		       FROM pg_catalog.pg_class AS relation
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = relation.relnamespace
		      WHERE namespace.nspname = 'public'
		        AND relation.relname = 'schema_migrations'
		     UNION
		     SELECT database_record.datdba
		       FROM pg_catalog.pg_database AS database_record
		      WHERE database_record.datname = pg_catalog.current_database()
		 ),
		 assumable_roles AS (
		     SELECT assumable_role.oid
		       FROM pg_catalog.pg_roles AS assumable_role
		      WHERE pg_catalog.pg_has_role(
		                session_user, assumable_role.oid, 'MEMBER'
		            )
		 ),
		 schema_migrations_relation AS (
		     SELECT relation.*
		       FROM pg_catalog.pg_class AS relation
		       JOIN pg_catalog.pg_namespace AS namespace
		         ON namespace.oid = relation.relnamespace
		      WHERE namespace.nspname = 'public'
		        AND relation.relname = 'schema_migrations'
		 )
		 SELECT
		     current_user = session_user AND
		     role.rolcanlogin AND
		     NOT role.rolsuper AND
		     NOT role.rolreplication AND
		     NOT role.rolbypassrls AND
		     NOT role.rolcreatedb AND
		     NOT role.rolcreaterole AND
		     (
		         SELECT pg_catalog.count(*) = 1 AND
		                COALESCE(pg_catalog.bool_and(
		                    activity.usesysid = role.oid AND
		                    activity.usename = role.rolname
		                ), FALSE)
		           FROM pg_catalog.pg_stat_activity AS activity
		          WHERE activity.pid = pg_catalog.pg_backend_pid()
		     ) AND
		     pg_catalog.has_schema_privilege(
		         session_user, 'hytch_push_vault', 'USAGE'
		     ) AND
		     pg_catalog.has_table_privilege(
		         session_user,
		         'hytch_push_vault.a3_directory_witness_heads',
		         'SELECT'
		     ) AND
		     pg_catalog.has_table_privilege(
		         session_user,
		         'hytch_push_vault.a3_directory_witness_heads',
		         'INSERT'
		     ) AND
		     pg_catalog.has_table_privilege(
		         session_user, 'public.schema_migrations', 'SELECT'
		     ) AND
		     (
		         SELECT pg_catalog.count(*) = 1 AND
		                COALESCE(pg_catalog.bool_and(
		                    migrations.relkind = 'r' AND
		                    migrations.relpersistence = 'p' AND
		                    NOT migrations.relispartition AND
		                    NOT migrations.relhassubclass AND
		                    NOT migrations.relhastriggers AND
		                    NOT migrations.relhasrules AND
		                    NOT migrations.relrowsecurity AND
		                    NOT migrations.relforcerowsecurity AND
		                    NOT EXISTS (
		                        SELECT 1
		                          FROM pg_catalog.pg_inherits AS inheritance
		                         WHERE inheritance.inhrelid = migrations.oid OR
		                               inheritance.inhparent = migrations.oid
		                    ) AND
		                    (
		                        SELECT (
		                                   (
		                                       pg_catalog.current_setting(
		                                           'server_version_num'
		                                       )::pg_catalog.int4 >= 130000 AND
		                                       pg_catalog.current_setting(
		                                           'server_version_num'
		                                       )::pg_catalog.int4 < 140000 AND
		                                       pg_catalog.count(*) = 1 AND
		                                       pg_catalog.count(*) FILTER (
		                                           WHERE constraint_record.contype = 'n'
		                                       ) = 0
		                                   ) OR (
		                                       pg_catalog.current_setting(
		                                           'server_version_num'
		                                       )::pg_catalog.int4 >= 180000 AND
		                                       pg_catalog.current_setting(
		                                           'server_version_num'
		                                       )::pg_catalog.int4 < 190000 AND
		                                       pg_catalog.count(*) = 3 AND
		                                       pg_catalog.count(*) FILTER (
		                                           WHERE constraint_record.contype = 'n'
		                                       ) = 2
		                                   )
		                               ) AND
		                               pg_catalog.count(*) FILTER (
		                                   WHERE constraint_record.contype <> 'n'
		                               ) = 1 AND
		                               pg_catalog.count(*) FILTER (
		                                   WHERE constraint_record.contype = 'p' AND
		                                         constraint_record.conkey =
		                                             ARRAY[1]::pg_catalog.int2[] AND
		                                         constraint_record.convalidated AND
		                                         NOT constraint_record.condeferrable AND
		                                         NOT constraint_record.condeferred AND
		                                         constraint_record.conislocal AND
		                                         constraint_record.coninhcount = 0 AND
		                                         constraint_record.connoinherit
		                               ) = 1
		                          FROM pg_catalog.pg_constraint AS constraint_record
		                         WHERE constraint_record.conrelid = migrations.oid
		                    ) AND
		                    NOT EXISTS (
		                        SELECT 1
		                          FROM pg_catalog.pg_trigger AS trigger
		                         WHERE trigger.tgrelid = migrations.oid
		                    ) AND
		                    NOT EXISTS (
		                        SELECT 1
		                          FROM pg_catalog.pg_policy AS policy
		                         WHERE policy.polrelid = migrations.oid
		                    ) AND
		                    NOT EXISTS (
		                        SELECT 1
		                          FROM pg_catalog.pg_rewrite AS rewrite_rule
		                         WHERE rewrite_rule.ev_class = migrations.oid
		                    ) AND
		                    (
		                        SELECT pg_catalog.count(*) = 2 AND
		                               COALESCE(pg_catalog.bool_and(
		                                   attribute.attnotnull AND
		                                   attribute.attidentity = '' AND
		                                   attribute.attgenerated = '' AND
		                                   NOT attribute.atthasdef AND
		                                   attribute.attacl IS NULL AND
		                                   attribute.attoptions IS NULL AND
		                                   attribute.attcollation = 0 AND
		                                   (
		                                       (
		                                           attribute.attnum = 1 AND
		                                           attribute.attname = 'version' AND
		                                           attribute.atttypid =
		                                               'pg_catalog.int8'
		                                                   ::pg_catalog.regtype
		                                       ) OR (
		                                           attribute.attnum = 2 AND
		                                           attribute.attname = 'dirty' AND
		                                           attribute.atttypid =
		                                               'pg_catalog.bool'
		                                                   ::pg_catalog.regtype
		                                       )
		                                   )
		                               ), FALSE)
		                          FROM pg_catalog.pg_attribute AS attribute
		                         WHERE attribute.attrelid = migrations.oid
		                           AND attribute.attnum > 0
		                           AND NOT attribute.attisdropped
		                    ) AND
		                    NOT EXISTS (
		                        SELECT 1
		                          FROM pg_catalog.aclexplode(
		                              COALESCE(
		                                  migrations.relacl,
		                                  pg_catalog.acldefault(
		                                      'r', migrations.relowner
		                                  )
		                              )
		                          ) AS privilege
		                         WHERE privilege.grantee <> migrations.relowner
		                           AND (
		                               privilege.grantee <> role.oid OR
		                               privilege.privilege_type <> 'SELECT' OR
		                               privilege.is_grantable
		                           )
		                    )
		                ), FALSE)
		           FROM schema_migrations_relation AS migrations
		     ) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM pg_catalog.pg_subscription AS subscription
		          WHERE subscription.subdbid = (
		              SELECT database_record.oid
		                FROM pg_catalog.pg_database AS database_record
		               WHERE database_record.datname =
		                     pg_catalog.current_database()
		          )
		     ) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM assumable_roles AS assumable_role
		          WHERE pg_catalog.has_schema_privilege(
		                    assumable_role.oid, 'public', 'CREATE'
		                ) OR
		                pg_catalog.has_schema_privilege(
		                    assumable_role.oid,
		                    'hytch_push_vault',
		                    'CREATE'
		                ) OR
		                pg_catalog.has_schema_privilege(
		                    assumable_role.oid,
		                    'hytch_push_vault',
		                    'USAGE WITH GRANT OPTION'
		                ) OR
		                pg_catalog.has_table_privilege(
		                    assumable_role.oid,
		                    'hytch_push_vault.a3_directory_witness_heads',
		                    'SELECT WITH GRANT OPTION'
		                ) OR
		                pg_catalog.has_table_privilege(
		                    assumable_role.oid,
		                    'hytch_push_vault.a3_directory_witness_heads',
		                    'INSERT WITH GRANT OPTION'
		                ) OR
		                pg_catalog.has_table_privilege(
		                    assumable_role.oid,
		                    'hytch_push_vault.a3_directory_witness_heads',
		                    'UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER'
		                ) OR
		                pg_catalog.has_function_privilege(
		                    assumable_role.oid,
		                    'hytch_push_vault.reject_a3_witness_mutation()',
		                    'EXECUTE'
		                )
		     ) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM protected_owners
		          WHERE pg_catalog.pg_has_role(
		              session_user, protected_owners.owner, 'MEMBER'
		          )
		     ) AND
		     NOT EXISTS (
		         SELECT 1
		           FROM pg_catalog.pg_roles AS powerful_role
		          WHERE (
		                    powerful_role.rolsuper OR
		                    powerful_role.rolreplication OR
		                    powerful_role.rolbypassrls OR
		                    powerful_role.rolcreatedb OR
		                    powerful_role.rolcreaterole OR
		                    powerful_role.rolname LIKE
		                        'pg\_%' ESCAPE '\'
		                )
		            AND pg_catalog.pg_has_role(
		                session_user, powerful_role.oid, 'MEMBER'
		            )
		     )
		   FROM pg_catalog.pg_roles AS role
		  WHERE role.rolname = session_user`,
	).Scan(&restrictedRuntimeRole); err != nil {
		return a3trust.ErrUnavailable
	}
	if !restrictedRuntimeRole {
		return ErrA3WitnessBarrierInvalid
	}
	if err = tx.Commit(); err != nil {
		return a3trust.ErrUnavailable
	}
	return nil
}

func a3WitnessSourceHashMatches(source, expected string) bool {
	digest := sha256.Sum256([]byte(source))
	return hex.EncodeToString(digest[:]) == expected
}

// RequireKeyContinuity fails activation if durable state was signed by a
// different witness key or if its latest receipt no longer verifies. An empty
// environment is valid and will bind to the key on its first accepted head.
func (store *A3WitnessStore) RequireKeyContinuity(
	ctx context.Context,
	environment string,
	publicKey ed25519.PublicKey,
) error {
	environmentID, ok := a9EnvironmentID(environment)
	if !ok || store == nil || store.db == nil || ctx == nil ||
		ctx.Err() != nil || len(publicKey) != ed25519.PublicKeySize ||
		a3trust.WitnessKeyID(publicKey) == "" {
		return a3trust.ErrUnavailable
	}
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		ReadOnly:  true,
	})
	if err != nil {
		return a3trust.ErrUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(
		ctx,
		`SELECT pg_catalog.pg_advisory_xact_lock($1, $2)`,
		a3WitnessLockClass,
		environmentID,
	); err != nil {
		return a3trust.ErrUnavailable
	}
	current, err := readLatestA3Witness(ctx, tx, environmentID)
	if errors.Is(err, sql.ErrNoRows) {
		if err = tx.Commit(); err != nil {
			return a3trust.ErrUnavailable
		}
		return nil
	}
	if err != nil || !validStoredA3Witness(current, environment, publicKey) {
		return a3trust.ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return a3trust.ErrUnavailable
	}
	return nil
}

func (store *A3WitnessStore) AcceptDirectoryTreeHead(
	ctx context.Context,
	proposal a3trust.WitnessProposal,
	privateKey ed25519.PrivateKey,
	keyID string,
) (a3trust.WitnessAcceptance, error) {
	environmentID, ok := a9EnvironmentID(proposal.Head.Environment)
	if !ok || len(privateKey) != ed25519.PrivateKeySize || store == nil ||
		store.db == nil || ctx == nil || ctx.Err() != nil {
		return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
	}
	publicKey, publicOK := privateKey.Public().(ed25519.PublicKey)
	canonical, canonicalErr := a3trust.CanonicalTreeHead(proposal.Head)
	if !publicOK ||
		len(publicKey) != ed25519.PublicKeySize ||
		keyID != a3trust.WitnessKeyID(publicKey) ||
		canonicalErr != nil || !bytes.Equal(canonical, proposal.CanonicalHead) ||
		!a3trust.VerifyWitnessExtension(proposal.Head, proposal.ConsistencyProof) {
		return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
	}
	proof := encodeWitnessProof(proposal.ConsistencyProof)
	// The transaction-scoped advisory lock is the serialization boundary. Use
	// READ COMMITTED so a waiter takes a fresh snapshot after the predecessor
	// commits instead of retaining a pre-lock SERIALIZABLE snapshot.
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(
		ctx,
		`SELECT pg_catalog.pg_advisory_xact_lock($1, $2)`,
		a3WitnessLockClass,
		environmentID,
	); err != nil {
		return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
	}

	current, err := readLatestA3Witness(ctx, tx, environmentID)
	if errors.Is(err, sql.ErrNoRows) {
		if !proposalTimeValidForStore(proposal, time.Now().UTC()) {
			return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
		}
		emptyRoot := sha256.Sum256(nil)
		priorRoot, decodeErr := hex.DecodeString(proposal.Head.PriorRootHash)
		if decodeErr != nil || proposal.Head.PriorTreeSize != 0 ||
			len(proof) != 0 || !bytes.Equal(priorRoot, emptyRoot[:]) {
			return a3trust.WitnessAcceptance{}, a3trust.ErrFork
		}
	} else if err != nil {
		return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
	} else {
		if current.acceptance.KeyID != keyID ||
			!validStoredA3Witness(current, proposal.Head.Environment, publicKey) {
			return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
		}
		if proposal.Head.TreeSize <= current.treeSize {
			stored, readErr := readA3WitnessAtPosition(
				ctx,
				tx,
				environmentID,
				proposal.Head.TreeSize,
			)
			if errors.Is(readErr, sql.ErrNoRows) {
				return a3trust.WitnessAcceptance{}, a3trust.ErrFork
			}
			if readErr != nil {
				return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
			}
			if !bytes.Equal(stored.canonical, proposal.CanonicalHead) ||
				!bytes.Equal(stored.proof, proof) {
				return a3trust.WitnessAcceptance{}, a3trust.ErrFork
			}
			if stored.acceptance.KeyID != keyID ||
				!ed25519.Verify(
					publicKey,
					stored.canonical,
					stored.acceptance.Signature[:],
				) {
				return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
			}
			if err = tx.Commit(); err != nil {
				return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
			}
			return stored.acceptance, nil
		}
		if !proposalTimeValidForStore(proposal, time.Now().UTC()) {
			return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
		}
		if proposal.Head.PriorTreeSize != current.treeSize ||
			proposal.Head.PriorRootHash != current.rootHash ||
			proposal.Head.TimestampMS < current.timestampMS {
			return a3trust.WitnessAcceptance{}, a3trust.ErrFork
		}
	}
	if !proposalTimeValidForStore(proposal, time.Now().UTC()) {
		return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
	}

	signature := ed25519.Sign(privateKey, proposal.CanonicalHead)
	rootHash, rootErr := hex.DecodeString(proposal.Head.RootHash)
	priorRootHash, priorErr := hex.DecodeString(proposal.Head.PriorRootHash)
	if rootErr != nil || priorErr != nil || len(signature) != ed25519.SignatureSize {
		return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
	}
	if _, err = tx.ExecContext(
		ctx,
		`INSERT INTO hytch_push_vault.a3_directory_witness_heads
		 (environment, tree_size, root_hash, prior_tree_size, prior_root_hash,
		  timestamp_ms, canonical_head, consistency_proof, witness_key_id,
		  witness_signature)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		environmentID,
		int64(proposal.Head.TreeSize),
		rootHash,
		int64(proposal.Head.PriorTreeSize),
		priorRootHash,
		int64(proposal.Head.TimestampMS),
		proposal.CanonicalHead,
		proof,
		keyID,
		signature,
	); err != nil {
		return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return a3trust.WitnessAcceptance{}, a3trust.ErrUnavailable
	}
	var accepted a3trust.WitnessAcceptance
	accepted.KeyID = keyID
	copy(accepted.Signature[:], signature)
	return accepted, nil
}

func proposalTimeValidForStore(
	proposal a3trust.WitnessProposal,
	now time.Time,
) bool {
	return !proposal.NotBefore.IsZero() && !proposal.NotAfter.IsZero() &&
		!now.Before(proposal.NotBefore) && !now.After(proposal.NotAfter)
}

type a3StoredWitness struct {
	treeSize      uint64
	rootHash      string
	priorTreeSize uint64
	priorRootHash string
	timestampMS   uint64
	canonical     []byte
	proof         []byte
	acceptance    a3trust.WitnessAcceptance
}

func readA3WitnessAtPosition(
	ctx context.Context,
	tx *sql.Tx,
	environmentID int16,
	treeSize uint64,
) (a3StoredWitness, error) {
	var (
		storedTreeSize int64
		rootHash       []byte
		signature      []byte
		result         a3StoredWitness
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT tree_size, root_hash, canonical_head, consistency_proof,
		        witness_key_id, witness_signature
		   FROM hytch_push_vault.a3_directory_witness_heads
		  WHERE environment = $1 AND tree_size = $2`,
		environmentID,
		int64(treeSize),
	).Scan(
		&storedTreeSize,
		&rootHash,
		&result.canonical,
		&result.proof,
		&result.acceptance.KeyID,
		&signature,
	)
	if err != nil {
		return a3StoredWitness{}, err
	}
	if storedTreeSize < 1 || len(rootHash) != sha256.Size ||
		len(signature) != ed25519.SignatureSize {
		return a3StoredWitness{}, a3trust.ErrUnavailable
	}
	result.treeSize = uint64(storedTreeSize)
	result.rootHash = hex.EncodeToString(rootHash)
	copy(result.acceptance.Signature[:], signature)
	result.acceptance.Replay = true
	return result, nil
}

func readLatestA3Witness(
	ctx context.Context,
	tx *sql.Tx,
	environmentID int16,
) (a3StoredWitness, error) {
	var (
		treeSize        int64
		rootHash        []byte
		priorTreeSize   int64
		priorRootHash   []byte
		resultTimestamp int64
		resultKeyID     string
		signature       []byte
		result          a3StoredWitness
	)
	err := tx.QueryRowContext(
		ctx,
		`SELECT tree_size, root_hash, prior_tree_size, prior_root_hash,
		        timestamp_ms, canonical_head, consistency_proof,
		        witness_key_id, witness_signature
		   FROM hytch_push_vault.a3_directory_witness_heads
		  WHERE environment = $1
		  ORDER BY tree_size DESC
		  LIMIT 1`,
		environmentID,
	).Scan(
		&treeSize,
		&rootHash,
		&priorTreeSize,
		&priorRootHash,
		&resultTimestamp,
		&result.canonical,
		&result.proof,
		&resultKeyID,
		&signature,
	)
	if err != nil {
		return a3StoredWitness{}, err
	}
	if treeSize < 1 || priorTreeSize < 0 || priorTreeSize >= treeSize ||
		resultTimestamp < 0 || len(rootHash) != sha256.Size ||
		len(priorRootHash) != sha256.Size ||
		len(signature) != ed25519.SignatureSize || resultKeyID == "" {
		return a3StoredWitness{}, a3trust.ErrUnavailable
	}
	result.treeSize = uint64(treeSize)
	result.rootHash = hex.EncodeToString(rootHash)
	result.priorTreeSize = uint64(priorTreeSize)
	result.priorRootHash = hex.EncodeToString(priorRootHash)
	result.timestampMS = uint64(resultTimestamp)
	result.acceptance.KeyID = resultKeyID
	copy(result.acceptance.Signature[:], signature)
	return result, nil
}

func validStoredA3Witness(
	stored a3StoredWitness,
	environment string,
	publicKey ed25519.PublicKey,
) bool {
	if stored.acceptance.KeyID != a3trust.WitnessKeyID(publicKey) ||
		len(stored.canonical) == 0 || len(stored.proof)%sha256.Size != 0 ||
		len(stored.proof)/sha256.Size > 64 {
		return false
	}
	proof := make([][32]byte, len(stored.proof)/sha256.Size)
	for index := range proof {
		copy(proof[index][:], stored.proof[index*sha256.Size:(index+1)*sha256.Size])
	}
	head := a3trust.TreeHead{
		Domain: "hytch.directory.tree-head/v1", Environment: environment,
		PriorRootHash: stored.priorRootHash,
		PriorTreeSize: stored.priorTreeSize,
		Protocol:      1, RootHash: stored.rootHash,
		TimestampMS: stored.timestampMS, TreeSize: stored.treeSize,
	}
	canonical, err := a3trust.CanonicalTreeHead(head)
	return err == nil && bytes.Equal(canonical, stored.canonical) &&
		a3trust.VerifyWitnessExtension(head, proof) &&
		ed25519.Verify(publicKey, stored.canonical, stored.acceptance.Signature[:])
}

func encodeWitnessProof(proof [][32]byte) []byte {
	encoded := make([]byte, 0, len(proof)*sha256.Size)
	for index := range proof {
		encoded = append(encoded, proof[index][:]...)
	}
	return encoded
}
