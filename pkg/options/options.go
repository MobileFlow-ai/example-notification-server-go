package options

type ApiOptions struct {
	Enabled bool `long:"api" description:"Enable the GRPC API server"`
	Port    int  `short:"p" long:"api-port" env:"API_PORT" default:"8080" description:"Port for the Connect GRPC API"`
}

type ApnsOptions struct {
	Enabled                bool   `long:"apns-enabled" env:"APNS_ENABLED" description:"Compatibility flag; true is rejected until the reviewed A9 and Gate 8 activation is implemented"`
	SecureWrapperRequired  bool   `long:"apns-secure-wrapper-required" env:"APNS_SECURE_WRAPPER_REQUIRED" description:"Reject APNS requests that do not carry a Gate 8 secure route"`
	SecureEnvironment      string `long:"apns-secure-environment" env:"APNS_SECURE_ENVIRONMENT" choice:"dev" choice:"production" default:"dev" description:"Logical environment bound into Gate 8 APNS wrappers"`
	RatePerSecond          int    `long:"apns-rate-per-second" env:"APNS_RATE_PER_SECOND" default:"50" description:"Provisional process-wide APNS token rate per second"`
	RateBurst              int    `long:"apns-rate-burst" env:"APNS_RATE_BURST" default:"50" description:"Provisional process-wide APNS token bucket burst"`
	MaxConcurrency         int    `long:"apns-max-concurrency" env:"APNS_MAX_CONCURRENCY" default:"8" description:"Provisional maximum concurrent APNS requests"`
	QueueCapacity          int    `long:"apns-queue-capacity" env:"APNS_QUEUE_CAPACITY" default:"5000" description:"Maximum encrypted durable APNS jobs before fail-closed backpressure"`
	QueuePollIntervalMs    int    `long:"apns-queue-poll-interval-ms" env:"APNS_QUEUE_POLL_INTERVAL_MS" default:"500" description:"Provisional durable APNS queue poll interval"`
	RequestTimeoutSeconds  int    `long:"apns-request-timeout-seconds" env:"APNS_REQUEST_TIMEOUT_SECONDS" default:"10" description:"Maximum duration of one APNS request"`
	InitialRetryDelayMs    int    `long:"apns-initial-retry-delay-ms" env:"APNS_INITIAL_RETRY_DELAY_MS" default:"500" description:"Provisional initial APNS transient retry delay"`
	MaxRetryDelayMs        int    `long:"apns-max-retry-delay-ms" env:"APNS_MAX_RETRY_DELAY_MS" default:"30000" description:"Provisional capped APNS transient retry delay"`
	ShutdownTimeoutSeconds int    `long:"apns-shutdown-timeout-seconds" env:"APNS_SHUTDOWN_TIMEOUT_SECONDS" default:"15" description:"Maximum APNS worker drain duration"`
	P8Certificate          string `long:"apns-p8-certificate" env:"APNS_P8_CERTIFICATE" description:".p8 certificate data for APNS"`
	P8CertificateBase64    string `long:"apns-p8-certificate-base64" env:"APNS_P8_CERTIFICATE_BASE64" description:"Base64-encoded .p8 certificate data for APNS"`
	P8CertificateFilePath  string `long:"apns-p8-certificate-file-path" env:"APNS_P8_CERTIFICATE_FILE_PATH" description:".p8 certificate file for APNS"`
	KeyId                  string `long:"apns-key-id" env:"APNS_KEY_ID" description:"Key ID associated with APNS credentials"`
	TeamId                 string `long:"apns-team-id" env:"APNS_TEAM_ID" description:"APNS Team ID"`
	Topic                  string `long:"apns-topic" env:"APNS_TOPIC" description:"Topic to be used on all messages"`
	Mode                   string `long:"apns-mode" env:"APNS_MODE" description:"Which APNS servers to deliver to, development or production" choice:"development" choice:"production" default:"development"`
}

type FcmOptions struct {
	Enabled         bool   `long:"fcm-enabled" env:"FCM_ENABLED" description:"Enable FCM sending"`
	CredentialsJson string `long:"fcm-credentials-json" env:"FCM_CREDENTIALS_JSON" description:"FCM Credentials"`
	ProjectId       string `long:"fcm-project-id" env:"FCM_PROJECT_ID" description:"FCM Project ID"`
}

type XmtpOptions struct {
	ListenerEnabled bool   `long:"xmtp-listener" description:"Consume XMTP messages and dispatch to configured delivery services; zero delivery services is allowed for blocked audit mode"`
	UseTls          bool   `long:"xmtp-listener-tls" description:"Whether to connect to XMTP network using TLS"`
	GrpcAddress     string `short:"x" long:"xmtp-address" env:"XMTP_GRPC_ADDRESS" description:"Address (including port) of XMTP GRPC server"`
	NumWorkers      int    `long:"num-workers" description:"Number of workers used to process messages" default:"50"`
	ListenerType    string `long:"listener-type" env:"LISTENER_TYPE" default:"v3" choice:"v3" choice:"v4" description:"Which listener type to use (v3 or v4)"`
}

type HttpDeliveryOptions struct {
	Enabled             bool   `long:"http-delivery"`
	Address             string `long:"http-delivery-address"`
	AuthHeader          string `long:"http-auth-header"`
	MaxAttempts         int    `long:"http-max-attempts" env:"HTTP_MAX_ATTEMPTS" default:"1" description:"Maximum number of delivery attempts (minimum 1, includes initial attempt)"`
	InitialRetryDelayMs int    `long:"http-initial-retry-delay-ms" env:"HTTP_INITIAL_RETRY_DELAY_MS" default:"250" description:"Initial retry delay in milliseconds (doubles with each retry)"`
}

type VaultOptions struct {
	Enabled                 bool   `long:"hytch-secure-vault" env:"HYTCH_SECURE_VAULT" description:"Enable authenticated Gate 8 routing vault and disable legacy registration APIs"`
	Environment             string `long:"bridge-environment" env:"BRIDGE_ENVIRONMENT" choice:"dev" choice:"production" default:"dev" description:"Logical bridge environment bound into signed authority and routing aliases"`
	MasterKeysJSON          string `long:"vault-master-keys-json" env:"BRIDGE_VAULT_MASTER_KEYS_JSON" description:"Versioned base64url 32-byte vault root keys as JSON"`
	LookupKey               string `long:"vault-lookup-key" env:"BRIDGE_VAULT_LOOKUP_KEY" description:"Base64url 32-byte domain-separated lookup root"`
	AuthorityPublicKeysJSON string `long:"authority-public-keys-json" env:"BRIDGE_AUTHORITY_PUBLIC_KEYS_JSON" description:"Versioned Ed25519 authority public keys as JSON"`
	APIBearerToken          string `long:"bridge-api-bearer-token" env:"BRIDGE_API_BEARER_TOKEN" description:"Legacy internal service credential; rejected when A9 asymmetric service authentication is enabled"`
	LeaseTTLHours           int    `long:"vault-lease-ttl-hours" env:"BRIDGE_VAULT_LEASE_TTL_HOURS" default:"168" description:"Authenticated subscription lease TTL, capped at 168 hours"`
	TeenConversationMode    string `long:"bridge-teen-conversation-mode" env:"BRIDGE_TEEN_CONVERSATION_MODE" choice:"disabled" choice:"enabled" default:"disabled" description:"Enable teen XMTP conversation routing only after the required safety review"`
	WelcomeEnabled          bool   `long:"bridge-welcome-enabled" env:"BRIDGE_WELCOME_ENABLED" description:"Compatibility flag; true is rejected because Welcome routing is unavailable in this build"`
}

type A9Options struct {
	Enabled                      bool   `long:"a9-enabled" env:"BRIDGE_A9_ENABLED" description:"Enable the root-pinned A9 authority control plane; does not by itself enable APNS or Welcome"`
	KeysetOrigin                 string `long:"a9-keyset-origin" env:"BRIDGE_A9_KEYSET_ORIGIN" description:"Exact private HTTPS modern-api origin used only for A9 keyset discovery"`
	PinnedRootPublicKeyBase64URL string `long:"a9-pinned-root-public-key" env:"BRIDGE_A9_PINNED_ROOT_PUBLIC_KEY" description:"Out-of-band canonical Base64url Ed25519 A9 root public key"`
	PinnedRootKeyID              string `long:"a9-pinned-root-key-id" env:"BRIDGE_A9_PINNED_ROOT_KEY_ID" description:"Out-of-band A9 root key ID derived from the pinned public key"`
	TopicCommitmentKeysJSON      string `long:"a9-topic-commitment-keys-json" env:"BRIDGE_A9_TOPIC_COMMITMENT_KEYS_JSON" description:"Deprecated inline A9 TOPIC secret material; any nonempty value is rejected"`
	TopicCommitmentKeysFilePath  string `long:"a9-topic-commitment-keys-file-path" env:"BRIDGE_A9_TOPIC_COMMITMENT_KEYS_FILE_PATH" description:"Absolute path to a restricted regular file containing bridge-only A9 TOPIC commitment key records"`
	KeysetRequestTimeoutSeconds  int    `long:"a9-keyset-request-timeout-seconds" env:"BRIDGE_A9_KEYSET_REQUEST_TIMEOUT_SECONDS" default:"10" description:"A9 private keyset discovery timeout, from 1 through 30 seconds"`
	PrivateBindAddress           string `long:"a9-private-bind" env:"BRIDGE_A9_PRIVATE_BIND" default:"127.0.0.1:9443" description:"Dedicated private TLS listener address for the A9 control plane"`
	AllowWildcardPrivateBind     bool   `long:"a9-allow-wildcard-private-bind" env:"BRIDGE_A9_ALLOW_WILDCARD_PRIVATE_BIND" description:"Permit an unspecified A9 bind only after deployment-level private-network isolation is independently verified"`
	TLSCertificateFilePath       string `long:"a9-tls-certificate-file-path" env:"BRIDGE_A9_TLS_CERTIFICATE_FILE_PATH" description:"Absolute path to the A9 private listener certificate PEM"`
	TLSPrivateKeyFilePath        string `long:"a9-tls-private-key-file-path" env:"BRIDGE_A9_TLS_PRIVATE_KEY_FILE_PATH" description:"Absolute path to the A9 private listener key PEM"`
	ReadHeaderTimeoutSeconds     int    `long:"a9-read-header-timeout-seconds" env:"BRIDGE_A9_READ_HEADER_TIMEOUT_SECONDS" default:"5" description:"A9 TLS listener header-read timeout"`
	ReadTimeoutSeconds           int    `long:"a9-read-timeout-seconds" env:"BRIDGE_A9_READ_TIMEOUT_SECONDS" default:"15" description:"A9 TLS listener complete-request read timeout"`
	WriteTimeoutSeconds          int    `long:"a9-write-timeout-seconds" env:"BRIDGE_A9_WRITE_TIMEOUT_SECONDS" default:"15" description:"A9 TLS listener response-write timeout"`
	IdleTimeoutSeconds           int    `long:"a9-idle-timeout-seconds" env:"BRIDGE_A9_IDLE_TIMEOUT_SECONDS" default:"30" description:"A9 TLS listener keep-alive idle timeout"`
	MaxHeaderBytes               int    `long:"a9-max-header-bytes" env:"BRIDGE_A9_MAX_HEADER_BYTES" default:"16384" description:"A9 TLS listener maximum request-header bytes"`
}

// HasTrustMaterial reports only security-sensitive A9 fields. The bounded
// timeout has a nonzero default and therefore is not configuration material.
func (options A9Options) HasTrustMaterial() bool {
	return options.KeysetOrigin != "" ||
		options.PinnedRootPublicKeyBase64URL != "" ||
		options.PinnedRootKeyID != "" ||
		options.TopicCommitmentKeysJSON != "" ||
		options.TopicCommitmentKeysFilePath != "" ||
		options.AllowWildcardPrivateBind ||
		options.TLSCertificateFilePath != "" ||
		options.TLSPrivateKeyFilePath != ""
}

type IncidentAccessOptions struct {
	Enabled                 bool   `long:"incident-access-enabled" env:"BRIDGE_INCIDENT_ACCESS_ENABLED" description:"Enable the private dual-control incident-access listener"`
	BindAddress             string `long:"incident-access-bind" env:"BRIDGE_INCIDENT_ACCESS_BIND" default:"127.0.0.1:9091" description:"Loopback address for the private incident-access listener"`
	ActorCredentialsJSON    string `long:"incident-actor-credentials-json" env:"BRIDGE_INCIDENT_ACTOR_CREDENTIALS_JSON" description:"Digest-only requester and approver credentials as JSON"`
	OversightWebhookURL     string `long:"incident-oversight-webhook-url" env:"BRIDGE_INCIDENT_OVERSIGHT_WEBHOOK_URL" description:"HTTPS oversight broadcast endpoint"`
	OversightWebhookBearer  string `long:"incident-oversight-webhook-bearer" env:"BRIDGE_INCIDENT_OVERSIGHT_WEBHOOK_BEARER" description:"Oversight endpoint bearer credential"`
	RoleTTLMinutes          int    `long:"incident-role-ttl-minutes" env:"BRIDGE_INCIDENT_ROLE_TTL_MINUTES" default:"30" description:"Approved incident-access lifetime, at most 120 minutes"`
	RequestTimeoutSeconds   int    `long:"incident-request-timeout-seconds" env:"BRIDGE_INCIDENT_REQUEST_TIMEOUT_SECONDS" default:"10" description:"Private incident request deadline"`
	OversightTimeoutSeconds int    `long:"incident-oversight-timeout-seconds" env:"BRIDGE_INCIDENT_OVERSIGHT_TIMEOUT_SECONDS" default:"5" description:"Oversight broadcast deadline"`
}

type Options struct {
	Api          ApiOptions            `group:"API Options"`
	Xmtp         XmtpOptions           `group:"Worker Options"`
	Apns         ApnsOptions           `group:"APNS Options"`
	Fcm          FcmOptions            `group:"FCM Options"`
	HttpDelivery HttpDeliveryOptions   `group:"HTTP Delivery Options"`
	Vault        VaultOptions          `group:"Hytch Secure Vault Options"`
	A9           A9Options             `group:"Hytch A9 Authority Options"`
	Incident     IncidentAccessOptions `group:"Incident Access Options"`

	DbConnectionString          string `short:"d" long:"db-connection-string" env:"DB_CONNECTION_STRING" description:"Address to database"`
	MigrationDbConnectionString string `long:"migration-db-connection-string" env:"MIGRATION_DB_CONNECTION_STRING" description:"Owner connection used only by the explicit migration command"`
	LogEncoding                 string `long:"log-encoding" env:"LOG_ENCODING" description:"Log encoding" choice:"console" choice:"json" default:"console"`
	LogLevel                    string `long:"log-level" env:"LOG_LEVEL" description:"log-level" choice:"debug" choice:"info" choice:"error" default:"info"`
	CreateMigration             string `long:"create-migration" description:"create a migration with the given name"`
	MigrateOnly                 bool   `long:"migrate-only" description:"Apply database migrations and exit without starting runtime surfaces"`
	PreflightLegacyRetirement   bool   `long:"preflight-legacy-retirement" description:"Run the read-only legacy routing retirement preflight and exit"`
	ProvisionA9Material         string `long:"provision-a9-material" choice:"topic-commitment-keys" choice:"tls-certificate" choice:"tls-private-key" description:"Read one A9 material item from stdin, create its configured file at mode 0600, and exit"`
	PreflightA9RuntimeFiles     bool   `long:"preflight-a9-runtime-files" description:"Validate the complete A9 runtime configuration and restricted file metadata without reading file contents, then exit"`
}

// APNSModeForBridgeEnvironment keeps the signed/wrapper environment vocabulary
// independent from the APNS provider endpoint vocabulary.
func APNSModeForBridgeEnvironment(environment string) (string, bool) {
	switch environment {
	case "dev":
		return "development", true
	case "production":
		return "production", true
	default:
		return "", false
	}
}
