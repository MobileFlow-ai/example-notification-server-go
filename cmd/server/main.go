package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/xmtp/example-notification-server-go/pkg/a3trust"
	"github.com/xmtp/example-notification-server-go/pkg/a9api"
	"github.com/xmtp/example-notification-server-go/pkg/api"
	"github.com/xmtp/example-notification-server-go/pkg/authority"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/delivery"
	"github.com/xmtp/example-notification-server-go/pkg/incidentaccess"
	"github.com/xmtp/example-notification-server-go/pkg/installations"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"github.com/xmtp/example-notification-server-go/pkg/logging"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"github.com/xmtp/example-notification-server-go/pkg/registration"
	"github.com/xmtp/example-notification-server-go/pkg/subscriptions"
	"github.com/xmtp/example-notification-server-go/pkg/vault"
	"github.com/xmtp/example-notification-server-go/pkg/xmtp"
	"go.uber.org/zap"
)

var opts options.Options
var logger *zap.Logger

var (
	GitCommit           string
	XMTPGoClientVersion string
)

const (
	retentionStartupTimeout            = 30 * time.Second
	legacyRetirementPreflightTimeout   = 20 * time.Second
	legacyRetirementPreflightDBWait    = 10 * time.Second
	maxSecureLeaseTTLHours             = 168
	maxXMTPListenerWorkers             = 128
	maxIncidentRoleTTLMinutes          = 120
	maxIncidentRequestTimeoutSeconds   = 30
	maxIncidentOversightTimeoutSeconds = 15
	maxA9KeysetRequestTimeoutSeconds   = 30
	maxA9ReadHeaderTimeoutSeconds      = 10
	maxA9RequestTimeoutSeconds         = 30
	maxA9IdleTimeoutSeconds            = 60
	minA9HeaderBytes                   = 4 * 1024
	maxA9HeaderBytes                   = 32 * 1024
)

func main() {
	preflightRequested := legacyRetirementPreflightRequested(os.Args[1:])
	if !runWithModeAwareFixedPanicBoundary(
		runServer,
		preflightRequested,
		os.Stderr,
	) {
		os.Exit(1)
	}
}

func runWithFixedPanicBoundary(run func()) (completed bool) {
	return runWithModeAwareFixedPanicBoundary(run, false, nil)
}

func runWithModeAwareFixedPanicBoundary(
	run func(),
	preflightRequested bool,
	stderr io.Writer,
) (completed bool) {
	defer func() {
		if recover() != nil {
			if preflightRequested {
				writeLegacyRetirementPreflightFailure(stderr)
			} else {
				log.Print("fatal runtime failure")
			}
			completed = false
		}
	}()
	run()
	return true
}

func runServer() {
	log.SetFlags(0)
	args := os.Args[1:]
	preflightRequested := legacyRetirementPreflightRequested(args)
	if preflightRequested &&
		legacyRetirementPreflightMigrationDSNOnCLI(args) {
		writeLegacyRetirementPreflightFailure(os.Stderr)
		os.Exit(1)
	}

	var err error
	parser := flags.NewParser(
		&opts,
		flags.HelpFlag|flags.PassDoubleDash,
	)
	if _, err = parser.ParseArgs(args); err != nil {
		if preflightRequested {
			writeLegacyRetirementPreflightFailure(os.Stderr)
			os.Exit(1)
		}
		if err, ok := err.(*flags.Error); !ok || err.Type != flags.ErrHelp {
			log.Fatal("option parsing failed")
		}
		parser.WriteHelp(os.Stdout)
		return
	}

	if preflightRequested {
		completed := runLegacyRetirementPreflightMode(
			context.Background(),
			opts,
			os.Stdout,
			os.Stderr,
			database.RunLegacyRetirementPreflight,
		)
		if !completed {
			os.Exit(1)
		}
		return
	}

	logger = logging.CreateLogger(opts.LogEncoding, opts.LogLevel)
	clientVersion := "example-notifications-server-go/" + shortGitCommit()
	appVersion := "xmtp-go/" + shortXMTPGoClientVersion()

	logger.Info("starting", zap.String("client-version", clientVersion), zap.String("app-version", appVersion))

	if opts.CreateMigration != "" {
		if err = createMigration(); err != nil {
			logger.Fatal("failed to create migration")
		}
		return
	}
	if opts.MigrateOnly {
		migrationDB := initMigrationDb()
		if err = migrationDB.Close(); err != nil {
			logger.Fatal("database migration connection close failed")
		}
		return
	}
	if !apnsRuntimeConfigurationValid(opts) {
		logger.Fatal("APNS egress unavailable in this build")
	}
	if !welcomeRuntimeConfigurationValid(opts.Vault.WelcomeEnabled) {
		logger.Fatal("welcome routing unavailable in this build")
	}
	if !a9RuntimeConfigurationValid(opts) {
		logger.Fatal("A9 authority configuration invalid")
	}
	if !a10RuntimeConfigurationValid(opts) {
		logger.Fatal("A10 registration configuration invalid")
	}
	if !a3RuntimeConfigurationValid(opts) {
		logger.Fatal("A3 directory trust configuration invalid")
	}
	if opts.MigrationDbConnectionString != "" {
		logger.Fatal("migration credential present in runtime")
	}

	if !opts.Xmtp.ListenerEnabled &&
		!opts.Api.Enabled &&
		!opts.Incident.Enabled {
		logger.Fatal("no runtime surface enabled")
	}
	if !opts.Incident.Enabled &&
		(opts.Incident.ActorCredentialsJSON != "" ||
			opts.Incident.OversightWebhookURL != "" ||
			opts.Incident.OversightWebhookBearer != "") {
		logger.Fatal("incident access configuration present while disabled")
	}
	if opts.Incident.Enabled && !opts.Vault.Enabled {
		logger.Fatal("incident access requires secure vault mode")
	}
	if opts.Xmtp.ListenerEnabled {
		if _, valid := checkedXMTPWorkerCount(
			opts.Xmtp.NumWorkers,
		); !valid {
			logger.Fatal("XMTP listener worker count invalid")
		}
	}
	var secureLeaseTTL time.Duration
	if opts.Vault.Enabled {
		var valid bool
		secureLeaseTTL, valid = checkedSecureLeaseTTL(
			opts.Vault.LeaseTTLHours,
		)
		if !valid {
			logger.Fatal("secure vault lease TTL invalid")
		}
	}

	db := initDb()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if opts.Vault.Enabled && (opts.Fcm.Enabled || opts.HttpDelivery.Enabled) {
		logger.Fatal("secure vault mode permits APNS delivery only")
	}
	var installationsService interfaces.Installations = installations.NewInstallationsService(logger, db)
	var subscriptionsService interfaces.Subscriptions = subscriptions.NewSubscriptionsService(logger, db)
	var secureRegistration *registration.Handler
	var encryptionKeys *vault.Keyring
	var lookupKey *vault.LookupKey
	var secureStore *vault.Store
	var retentionSweeper *vault.RetentionSweeper
	var erasureWorker *delivery.InvalidTokenErasureWorker
	var a9TrustHandle *vault.A9TrustHandle
	var a9ControlRuntime *a9Runtime
	var a10RegistrationRuntime *a10Runtime
	var a3TrustRuntime *a3Runtime
	if opts.Vault.Enabled {
		var parseErr error
		encryptionKeys, parseErr = vault.ParseKeyring(opts.Vault.MasterKeysJSON)
		if parseErr != nil {
			logger.Fatal("secure vault key state invalid")
		}
		lookupKey, parseErr = vault.ParseLookupKey(opts.Vault.LookupKey)
		if parseErr != nil {
			logger.Fatal("secure vault lookup state invalid")
		}
		authorityKeys, parseErr := authority.ParsePublicKeyring(
			opts.Vault.AuthorityPublicKeysJSON,
		)
		if parseErr != nil {
			logger.Fatal("authority key state invalid")
		}
		if opts.A9.Enabled {
			a9TrustHandle = &vault.A9TrustHandle{}
		}
		var storeErr error
		secureStore, storeErr = vault.NewStore(db, vault.StoreOptions{
			Environment:   opts.Vault.Environment,
			LeaseTTL:      secureLeaseTTL,
			Encryption:    encryptionKeys,
			Lookup:        lookupKey,
			AuthorityKeys: authorityKeys,
			TeenConversationEnabled: opts.Vault.
				TeenConversationMode == "enabled",
			WelcomeEnabled: false,
			A9Enabled:      opts.A9.Enabled,
			A9Trust:        a9TrustHandle,
		})
		if storeErr != nil {
			logger.Fatal("secure vault initialization failed")
		}
		// This database-wide gate is read-only during routine startup. Legacy
		// retirement and activation require a separately authorized maintenance
		// transaction on a proven dedicated database.
		if storeErr = secureStore.
			RequireLegacyPlaintextRoutingDisabled(ctx); storeErr != nil {
			logger.Fatal("legacy plaintext routing gate failed")
		}
		if storeErr = secureStore.
			RequireAccessAuditBarrier(ctx); storeErr != nil {
			logger.Fatal("access audit barrier failed")
		}
		retentionSweeper, storeErr = vault.NewRetentionSweeper(
			db,
			vault.RetentionOptions{
				SweepInterval:        15 * time.Minute,
				Environment:          opts.Vault.Environment,
				Lookup:               lookupKey,
				EncryptionKeyVersion: encryptionKeys.ActiveVersion(),
			},
		)
		if storeErr != nil {
			logger.Fatal("retention control initialization failed")
		}
		erasureWorker, storeErr = delivery.NewInvalidTokenErasureWorker(
			logger,
			secureStore,
			secureStore,
		)
		if storeErr != nil {
			logger.Fatal("invalid-token erasure initialization failed")
		}
		// The same vault boundary serves registration and listener routing.
		// Leaving either listener dependency on the legacy plaintext tables
		// would silently bypass the short-lived capability and lease checks.
		installationsService = secureStore
		subscriptionsService = secureStore
		secureRegistration, storeErr = secureRegistrationForMode(
			secureStore,
			opts.Vault.APIBearerToken,
			opts.A9.Enabled,
		)
		if storeErr != nil {
			logger.Fatal("secure registration initialization failed")
		}
	}
	if opts.A9.Enabled {
		a9ControlRuntime, err = initializeA9Runtime(
			ctx,
			opts.A9,
			opts.Vault.Environment,
			db,
			secureStore,
			a9TrustHandle,
		)
		if err != nil {
			logger.Fatal("A9 authority initialization failed")
		}
	}
	if opts.A10.Enabled {
		a10RegistrationRuntime, err = initializeA10Runtime(
			ctx,
			opts.A10,
			opts.Vault.Environment,
			opts.Apns.Topic,
			db,
			secureStore,
		)
		if err != nil {
			logger.Fatal("A10 registration initialization failed")
		}
	}
	if opts.A3.AssociationEnabled || opts.A3.WitnessEnabled {
		a3TrustRuntime, err = initializeA3Runtime(
			ctx,
			opts.A3,
			opts.Vault.Environment,
			db,
		)
		if err != nil {
			logger.Fatal("A3 directory trust initialization failed")
		}
	}
	var notifListener xmtp.NotificationListener
	var apiServer *api.ApiServer
	var apnsService *delivery.ApnsDelivery
	var incidentServer *incidentaccess.Server

	if opts.Incident.Enabled {
		roleTTL, requestTimeout, oversightTimeout, valid :=
			checkedIncidentDurations(
				opts.Incident.RoleTTLMinutes,
				opts.Incident.RequestTimeoutSeconds,
				opts.Incident.OversightTimeoutSeconds,
			)
		if !valid {
			logger.Fatal("incident access timing configuration invalid")
		}
		authenticator, authorizedApprovers, configErr :=
			incidentaccess.ParseActorCredentials(
				opts.Incident.ActorCredentialsJSON,
			)
		if configErr != nil {
			logger.Fatal("incident actor credential state invalid")
		}
		broadcast, configErr :=
			incidentaccess.NewOversightWebhookBroadcast(
				opts.Incident.OversightWebhookURL,
				opts.Incident.OversightWebhookBearer,
				oversightTimeout,
			)
		if configErr != nil {
			logger.Fatal("incident oversight configuration invalid")
		}
		incidentGate, configErr := vault.NewIncidentAccessGate(
			db,
			vault.IncidentAccessOptions{
				Environment:         opts.Vault.Environment,
				RoleTTL:             roleTTL,
				AuthorizedApprovers: authorizedApprovers,
				Broadcast:           broadcast,
			},
		)
		if configErr != nil {
			logger.Fatal("incident access gate initialization failed")
		}
		incidentHandler, configErr := incidentaccess.NewHandler(
			incidentGate,
			authenticator,
		)
		if configErr != nil {
			logger.Fatal("incident access handler initialization failed")
		}
		incidentServer, configErr = incidentaccess.NewServer(
			logger,
			incidentHandler,
			incidentaccess.ServerOptions{
				BindAddress:    opts.Incident.BindAddress,
				RequestTimeout: requestTimeout,
			},
		)
		if configErr != nil {
			logger.Fatal("incident access listener initialization failed")
		}
	}

	if opts.Xmtp.ListenerEnabled {
		deliveryServices := []interfaces.Delivery{}
		var err error

		if opts.Apns.Enabled {
			if opts.Vault.Enabled {
				opts.Apns.SecureWrapperRequired = true
				opts.Apns.SecureEnvironment = opts.Vault.Environment
			}
			if opts.Vault.Enabled {
				apnsService, err = delivery.NewReliableApnsDelivery(
					logger,
					opts.Apns,
					secureStore,
				)
			} else {
				apnsService, err = delivery.NewApnsDelivery(logger, opts.Apns)
			}
			if err != nil {
				logger.Fatal("failed to initialize APNS")
			}
			deliveryServices = append(deliveryServices, apnsService)
		}

		if opts.Fcm.Enabled {
			fcm, err := delivery.NewFcmDelivery(ctx, logger, opts.Fcm)
			if err != nil {
				logger.Fatal("failed to initialize FCM")
			}
			deliveryServices = append(deliveryServices, fcm)
		}

		if opts.HttpDelivery.Enabled {
			deliveryServices = append(deliveryServices, delivery.NewHttpDelivery(logger, opts.HttpDelivery))
		}

		switch opts.Xmtp.ListenerType {
		case "v4":
			notifListener, err = xmtp.NewV4Listener(ctx, logger, opts.Xmtp, installationsService, subscriptionsService, deliveryServices, clientVersion, appVersion)
		default: // "v3"
			notifListener, err = xmtp.NewListener(ctx, logger, opts.Xmtp, installationsService, subscriptionsService, deliveryServices, clientVersion, appVersion)
		}
		if err != nil {
			logger.Fatal("failed to initialize listener")
		}
	}

	if opts.Api.Enabled {
		apiServer = api.NewApiServer(logger, opts.Api, installationsService, subscriptionsService, interfaces.ListenerType(opts.Xmtp.ListenerType))
		if err = configureRuntimeRegistrationAPI(
			apiServer,
			opts.A9.Enabled,
			secureRegistration,
			a10RegistrationRuntime,
		); err != nil {
			logger.Fatal("failed to enable A10 registration")
		}
		if a3TrustRuntime != nil {
			var associationHandler http.Handler
			var witnessHandler http.Handler
			if a3TrustRuntime.association != nil {
				associationHandler = a3TrustRuntime.association
			}
			if a3TrustRuntime.witness != nil {
				witnessHandler = a3TrustRuntime.witness
			}
			if err = apiServer.EnableA3TrustSurfaces(
				associationHandler,
				witnessHandler,
			); err != nil {
				logger.Fatal("failed to enable A3 directory trust")
			}
		}
		if notifListener != nil {
			apiServer.SetXMTPReadyCheck(notifListener.Ready)
		}
		apiServer.SetReadyCheck(func() bool {
			if notifListener != nil && !notifListener.Ready() {
				return false
			}
			if apnsService != nil && !apnsService.Ready() {
				return false
			}
			if erasureWorker != nil && !erasureWorker.Ready() {
				return false
			}
			if incidentServer != nil && !incidentServer.Ready() {
				return false
			}
			if a9ControlRuntime != nil &&
				(!a9ControlRuntime.private.Ready() ||
					!a9TrustReady(a9ControlRuntime.manager)) {
				return false
			}
			if a10RegistrationRuntime != nil &&
				!a10TrustReady(a10RegistrationRuntime.manager) {
				return false
			}
			if retentionSweeper == nil {
				return true
			}
			readyContext, readyCancel := context.WithTimeout(
				context.Background(),
				time.Second,
			)
			defer readyCancel()
			return retentionSweeper.Ready(readyContext) == nil
		})
	}

	if secureStore != nil {
		// Deletion recovery is the only worker permitted before the retention
		// and restore gates. It has no APNS client and cannot create egress.
		if err = erasureWorker.Start(ctx); err != nil {
			logger.Fatal("invalid-token erasure startup failed")
		}
		go func() {
			defer func() {
				if recover() != nil {
					logger.Error("invalid-token erasure monitor stopped")
					cancel()
				}
			}()
			select {
			case <-erasureWorker.Failed():
				logger.Error("invalid-token erasure worker stopped")
				cancel()
			case <-ctx.Done():
			}
		}()
		if err = ensureRetentionReady(ctx, retentionSweeper); err != nil {
			logger.Fatal("initial retention sweep failed")
		}
		// A controlled tombstone export is imported by the operator before
		// process start. Reapply it before the listener, registration API, or
		// APNS worker can observe restored routing state.
		if err = secureStore.ReapplyDeletionTombstones(ctx); err != nil {
			logger.Fatal("deletion recovery gate failed")
		}
		if err = ensureRetentionReady(ctx, retentionSweeper); err != nil {
			logger.Fatal("post-recovery retention sweep failed")
		}
		// Run retries all operational failures. Returning while the runtime is
		// active, or panicking, means the worker can no longer enforce
		// retention and must stop the process without exposing failure data.
		go runRetentionWorker(
			ctx,
			retentionSweeper.Run,
			logger,
			cancel,
		)
	}

	// Constructors above validate dependencies but do not enable egress.
	// Runtime surfaces are deliberately started only after all secure-mode
	// startup gates complete.
	if apiServer != nil {
		if err = apiServer.Prepare(); err != nil {
			logger.Fatal("failed to prepare API")
		}
	}
	if incidentServer != nil {
		if err = incidentServer.Prepare(); err != nil {
			logger.Fatal("failed to prepare private incident access listener")
		}
	}
	if a9ControlRuntime != nil {
		if err = a9ControlRuntime.private.Start(); err != nil {
			logger.Fatal("failed to start private A9 authority listener")
		}
		go monitorA9PrivateSurfaceFailure(
			ctx,
			a9ControlRuntime.private.Failed(),
			logger,
			cancel,
		)
		go runA9RefreshWorker(
			ctx,
			a9ControlRuntime.manager,
			logger,
			cancel,
		)
	}
	if a10RegistrationRuntime != nil {
		go runA10RefreshWorker(
			ctx,
			a10RegistrationRuntime.manager,
			logger,
			cancel,
		)
	}
	if incidentServer != nil {
		if err = incidentServer.Start(); err != nil {
			logger.Fatal("failed to start private incident access listener")
		}
		go func() {
			defer func() {
				if recover() != nil {
					logger.Error("incident access monitor stopped")
					cancel()
				}
			}()
			select {
			case <-incidentServer.Failed():
				logger.Error("incident access listener stopped")
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	if apnsService != nil {
		if err = apnsService.Start(ctx); err != nil {
			logger.Fatal("failed to start APNS")
		}
		if failed := apnsService.Failed(); failed != nil {
			go func() {
				defer func() {
					if recover() != nil {
						logger.Error("APNS monitor stopped")
						cancel()
					}
				}()
				select {
				case <-failed:
					logger.Error("APNS worker stopped")
					cancel()
				case <-ctx.Done():
				}
			}()
		}
	}
	if notifListener != nil {
		notifListener.Start()
		if failed := notifListener.Failed(); failed != nil {
			go monitorXMTPListenerFailure(
				ctx,
				failed,
				logger,
				cancel,
			)
		}
	}
	if apiServer != nil {
		if err = apiServer.Start(); err != nil {
			logger.Fatal("failed to start API")
		}
		if failed := apiServer.Failed(); failed != nil {
			go func() {
				defer func() {
					if recover() != nil {
						logger.Error("API monitor stopped")
						cancel()
					}
				}()
				select {
				case <-failed:
					logger.Error("API worker stopped")
					cancel()
				case <-ctx.Done():
				}
			}()
		}
	}

	runtimeFailed := waitForShutdown(ctx)

	if a9ControlRuntime != nil {
		// Stop future refresh attempts before closing the private ingress.
		// The manager remains live until every routing/egress consumer below
		// has stopped.
		cancel()
		shutdownContext, shutdownCancel := context.WithTimeout(
			context.Background(),
			30*time.Second,
		)
		if err = a9ControlRuntime.private.
			Shutdown(shutdownContext); err != nil {
			logger.Error("A9 private authority shutdown incomplete")
			runtimeFailed = true
		}
		shutdownCancel()
	}
	if apiServer != nil {
		apiServer.Stop()
	}
	if incidentServer != nil {
		shutdownContext, shutdownCancel := context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
		if err = incidentServer.Stop(shutdownContext); err != nil {
			logger.Error("incident access shutdown incomplete")
		}
		shutdownCancel()
	}

	if notifListener != nil {
		notifListener.Stop()
	}

	if apnsService != nil {
		shutdownSeconds := opts.Apns.ShutdownTimeoutSeconds
		if shutdownSeconds <= 0 {
			shutdownSeconds = 15
		}
		shutdownContext, shutdownCancel := context.WithTimeout(
			context.Background(),
			time.Duration(shutdownSeconds)*time.Second,
		)
		if err = apnsService.Stop(shutdownContext); err != nil {
			logger.Error("APNS shutdown incomplete")
		}
		shutdownCancel()
	}
	if erasureWorker != nil {
		shutdownContext, shutdownCancel := context.WithTimeout(
			context.Background(),
			15*time.Second,
		)
		if err = erasureWorker.Stop(shutdownContext); err != nil {
			logger.Error("invalid-token erasure shutdown incomplete")
		}
		shutdownCancel()
	}
	if a9ControlRuntime != nil {
		shutdownContext, shutdownCancel := context.WithTimeout(
			context.Background(),
			45*time.Second,
		)
		if err = a9ControlRuntime.manager.
			CloseContext(shutdownContext); err != nil {
			logger.Error("A9 trust shutdown incomplete")
			runtimeFailed = true
		}
		shutdownCancel()
	}
	if a3TrustRuntime != nil {
		if err = a3TrustRuntime.Close(); err != nil {
			logger.Error("A3 directory trust shutdown incomplete")
			runtimeFailed = true
		}
	}
	if runtimeFailed {
		panic("runtime control failed")
	}
}

func configureRuntimeRegistrationAPI(
	apiServer *api.ApiServer,
	a9Enabled bool,
	secureRegistration *registration.Handler,
	a10RegistrationRuntime *a10Runtime,
) error {
	if apiServer == nil {
		return api.ErrAPIUnavailable
	}
	if a9Enabled {
		apiServer.DisableLegacyMutationAPI()
	} else if secureRegistration != nil {
		apiServer.EnableSecureRegistration(secureRegistration)
	}
	if a10RegistrationRuntime == nil {
		return nil
	}
	return apiServer.EnableA10Registration(
		a10RegistrationRuntime.handler,
	)
}

func welcomeRuntimeConfigurationValid(enabled bool) bool {
	return !enabled
}

func apnsRuntimeConfigurationValid(config options.Options) bool {
	if !config.Apns.Enabled {
		return true
	}
	return config.A10.Enabled &&
		config.A9.Enabled &&
		config.Vault.Enabled &&
		config.Api.Enabled &&
		config.Xmtp.ListenerEnabled &&
		config.Xmtp.ListenerType == "v4" &&
		config.Vault.Environment == "dev" &&
		config.Apns.SecureWrapperRequired &&
		config.Apns.SecureEnvironment == "dev" &&
		config.Apns.Topic == "com.mobileflow.hytchdev" &&
		config.Apns.Mode == "development" &&
		config.Apns.P8Certificate == "" &&
		config.Apns.P8CertificateBase64 != "" &&
		config.Apns.P8CertificateFilePath == "" &&
		config.Apns.KeyId != "" &&
		config.Apns.TeamId != ""
}

func a10RuntimeConfigurationValid(config options.Options) bool {
	if !config.A10.Enabled {
		return !config.A10.HasTrustMaterial()
	}
	return config.Apns.Enabled &&
		config.A9.Enabled &&
		config.Vault.Enabled &&
		config.Api.Enabled &&
		config.Xmtp.ListenerEnabled &&
		config.Xmtp.ListenerType == "v4" &&
		config.Vault.Environment == "dev" &&
		config.A10.KeysetOrigin != "" &&
		config.A10.PinnedRootPublicKeyBase64URL != "" &&
		config.A10.PinnedRootKeyID != "" &&
		config.A10.KeysetRequestTimeoutSeconds >= 1 &&
		config.A10.KeysetRequestTimeoutSeconds <=
			maxA9KeysetRequestTimeoutSeconds
}

func a3RuntimeConfigurationValid(config options.Options) bool {
	associationMaterial := config.A3.AssociationBearerToken != "" ||
		config.A3.IdentityGRPCAddress != "" ||
		config.A3.ValidationGRPCAddress != "" ||
		config.A3.ValidationAllowPlaintextLoopback
	witnessMaterial := config.A3.WitnessBearerToken != "" ||
		config.A3.WitnessSeedFilePath != "" ||
		config.A3.WitnessSequencerPublicKeysJSON != ""
	if !config.A3.AssociationEnabled && !config.A3.WitnessEnabled {
		return !associationMaterial && !witnessMaterial
	}
	if !config.Api.Enabled ||
		(config.Vault.Environment != "dev" && config.Vault.Environment != "production") ||
		(config.Vault.APIBearerToken != "" &&
			(config.A3.AssociationBearerToken == config.Vault.APIBearerToken ||
				config.A3.WitnessBearerToken == config.Vault.APIBearerToken)) ||
		(!config.A3.AssociationEnabled && associationMaterial) ||
		(!config.A3.WitnessEnabled && witnessMaterial) {
		return false
	}
	if config.A3.AssociationEnabled {
		if !validA3OpaqueBearer(config.A3.AssociationBearerToken) ||
			!validA3IdentityTarget(
				config.Vault.Environment,
				config.A3.IdentityGRPCAddress,
			) ||
			!validA3GRPCTarget(
				config.A3.ValidationGRPCAddress,
				!config.A3.ValidationAllowPlaintextLoopback,
			) ||
			config.A3.AssociationRequestTimeoutSeconds < 1 ||
			config.A3.AssociationRequestTimeoutSeconds > 30 ||
			config.A3.AssociationMaximumClockSkewSec < 0 ||
			config.A3.AssociationMaximumClockSkewSec > 3600 ||
			config.A3.AssociationMaxPages < 1 || config.A3.AssociationMaxPages > 128 ||
			config.A3.AssociationMaxPageUpdates < 1 || config.A3.AssociationMaxPageUpdates > 1024 ||
			config.A3.AssociationMaxPageUpdates > config.A3.AssociationMaxUpdates ||
			config.A3.AssociationMaxUpdates < 1 || config.A3.AssociationMaxUpdates > 1024 ||
			config.A3.AssociationMaxUpdateBytes < 256 ||
			config.A3.AssociationMaxUpdateBytes > 1024*1024 ||
			config.A3.AssociationMaxHistoryBytes < config.A3.AssociationMaxUpdateBytes ||
			config.A3.AssociationMaxHistoryBytes > 16*1024*1024 ||
			config.A3.AssociationMaxValidationBytes < config.A3.AssociationMaxHistoryBytes ||
			config.A3.AssociationMaxValidationBytes > 128*1024*1024 ||
			config.A3.AssociationMaxConcurrency < 1 || config.A3.AssociationMaxConcurrency > 64 ||
			config.A3.AssociationRatePerSecond < 1 || config.A3.AssociationRatePerSecond > 1000 ||
			config.A3.AssociationRateBurst < 1 || config.A3.AssociationRateBurst > 1000 {
			return false
		}
	}
	if config.A3.WitnessEnabled {
		if !validA3OpaqueBearer(config.A3.WitnessBearerToken) ||
			!filepath.IsAbs(config.A3.WitnessSeedFilePath) ||
			config.A3.WitnessSequencerPublicKeysJSON == "" ||
			config.A3.WitnessRequestTimeoutSeconds < 1 ||
			config.A3.WitnessRequestTimeoutSeconds > 30 ||
			config.A3.WitnessMaximumAgeSeconds < 1 || config.A3.WitnessMaximumAgeSeconds > 86400 ||
			config.A3.WitnessMaximumClockSkewSec < 0 || config.A3.WitnessMaximumClockSkewSec > 3600 ||
			config.A3.WitnessMaxConcurrency < 1 || config.A3.WitnessMaxConcurrency > 64 ||
			config.A3.WitnessRatePerSecond < 1 || config.A3.WitnessRatePerSecond > 1000 ||
			config.A3.WitnessRateBurst < 1 || config.A3.WitnessRateBurst > 1000 {
			return false
		}
	}
	return !config.A3.AssociationEnabled || !config.A3.WitnessEnabled ||
		config.A3.AssociationBearerToken != config.A3.WitnessBearerToken
}

func validA3OpaqueBearer(value string) bool {
	return a3trust.ValidOpaqueBearer(value)
}

func a9RuntimeConfigurationValid(config options.Options) bool {
	if !config.A9.Enabled {
		return !config.A9.HasTrustMaterial()
	}
	if !config.Vault.Enabled ||
		!config.Api.Enabled ||
		!config.Xmtp.ListenerEnabled ||
		config.Xmtp.ListenerType != "v4" ||
		config.Vault.APIBearerToken != "" ||
		config.A9.KeysetOrigin == "" ||
		config.A9.PinnedRootPublicKeyBase64URL == "" ||
		config.A9.PinnedRootKeyID == "" ||
		config.A9.TopicCommitmentKeysJSON != "" ||
		config.A9.TopicCommitmentKeysFilePath == "" ||
		!filepath.IsAbs(config.A9.TopicCommitmentKeysFilePath) ||
		config.A9.KeysetRequestTimeoutSeconds < 1 ||
		config.A9.KeysetRequestTimeoutSeconds >
			maxA9KeysetRequestTimeoutSeconds {
		return false
	}
	if _, valid := checkedA9PrivateServerOptions(config.A9); !valid {
		return false
	}
	return true
}

func checkedA9PrivateServerOptions(
	config options.A9Options,
) (a9api.PrivateServerOptions, bool) {
	if config.ReadHeaderTimeoutSeconds < 1 ||
		config.ReadHeaderTimeoutSeconds >
			maxA9ReadHeaderTimeoutSeconds ||
		config.ReadTimeoutSeconds <
			config.ReadHeaderTimeoutSeconds ||
		config.ReadTimeoutSeconds >
			maxA9RequestTimeoutSeconds ||
		config.WriteTimeoutSeconds < 1 ||
		config.WriteTimeoutSeconds >
			maxA9RequestTimeoutSeconds ||
		config.IdleTimeoutSeconds < 1 ||
		config.IdleTimeoutSeconds >
			maxA9IdleTimeoutSeconds ||
		config.MaxHeaderBytes < minA9HeaderBytes ||
		config.MaxHeaderBytes > maxA9HeaderBytes {
		return a9api.PrivateServerOptions{}, false
	}
	serverOptions := a9api.PrivateServerOptions{
		BindAddress:          config.PrivateBindAddress,
		AllowUnspecifiedBind: config.AllowWildcardPrivateBind,
		CertificatePath:      config.TLSCertificateFilePath,
		PrivateKeyPath:       config.TLSPrivateKeyFilePath,
		ReadHeaderTimeout: time.Duration(
			config.ReadHeaderTimeoutSeconds,
		) * time.Second,
		ReadTimeout: time.Duration(
			config.ReadTimeoutSeconds,
		) * time.Second,
		WriteTimeout: time.Duration(
			config.WriteTimeoutSeconds,
		) * time.Second,
		IdleTimeout: time.Duration(
			config.IdleTimeoutSeconds,
		) * time.Second,
		MaxHeaderBytes: config.MaxHeaderBytes,
	}
	if a9api.ValidatePrivateServerOptions(serverOptions) != nil {
		return a9api.PrivateServerOptions{}, false
	}
	return serverOptions, true
}

func checkedSecureLeaseTTL(hours int) (time.Duration, bool) {
	// Validate the integer before converting to time.Duration so a
	// maliciously large environment value cannot overflow into an apparently
	// valid short lease.
	if hours < 1 || hours > maxSecureLeaseTTLHours {
		return 0, false
	}
	return time.Duration(hours) * time.Hour, true
}

func checkedXMTPWorkerCount(workers int) (int, bool) {
	if workers < 1 || workers > maxXMTPListenerWorkers {
		return 0, false
	}
	return workers, true
}

func checkedIncidentDurations(
	roleTTLMinutes int,
	requestTimeoutSeconds int,
	oversightTimeoutSeconds int,
) (time.Duration, time.Duration, time.Duration, bool) {
	if roleTTLMinutes < 1 ||
		roleTTLMinutes > maxIncidentRoleTTLMinutes ||
		requestTimeoutSeconds < 1 ||
		requestTimeoutSeconds > maxIncidentRequestTimeoutSeconds ||
		oversightTimeoutSeconds < 1 ||
		oversightTimeoutSeconds >
			maxIncidentOversightTimeoutSeconds {
		return 0, 0, 0, false
	}
	return time.Duration(roleTTLMinutes) * time.Minute,
		time.Duration(requestTimeoutSeconds) * time.Second,
		time.Duration(oversightTimeoutSeconds) * time.Second,
		true
}

func ensureRetentionReady(
	ctx context.Context,
	retentionSweeper *vault.RetentionSweeper,
) error {
	if retentionSweeper == nil {
		return nil
	}
	retentionContext, retentionCancel := context.WithTimeout(
		ctx,
		retentionStartupTimeout,
	)
	defer retentionCancel()
	return retentionSweeper.EnsureReady(retentionContext)
}

func monitorXMTPListenerFailure(
	ctx context.Context,
	failed <-chan struct{},
	runtimeLogger *zap.Logger,
	cancel context.CancelFunc,
) {
	if failed == nil {
		return
	}
	defer func() {
		if recover() != nil {
			if cancel != nil {
				cancel()
			}
			if runtimeLogger != nil {
				runtimeLogger.Error("XMTP listener monitor stopped")
			}
		}
	}()
	select {
	case <-failed:
		if cancel != nil {
			cancel()
		}
		if runtimeLogger != nil {
			runtimeLogger.Error("XMTP listener stopped")
		}
	case <-ctx.Done():
	}
}

func runRetentionWorker(
	ctx context.Context,
	run func(context.Context) error,
	runtimeLogger *zap.Logger,
	cancel context.CancelFunc,
) {
	defer func() {
		if recover() != nil {
			if cancel != nil {
				cancel()
			}
			if runtimeLogger != nil {
				runtimeLogger.Error("retention worker stopped")
			}
		}
	}()
	if run == nil {
		return
	}
	_ = run(ctx)
	if ctx.Err() != nil {
		return
	}
	if cancel != nil {
		cancel()
	}
	if runtimeLogger != nil {
		runtimeLogger.Error("retention worker stopped")
	}
}

// Commenting out as these are currently unused
func waitForShutdown(ctx context.Context) bool {
	termChannel := make(chan os.Signal, 1)
	signal.Notify(termChannel, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(termChannel)
	select {
	case <-termChannel:
		return false
	case <-ctx.Done():
		return true
	}
}

func initDb() *sql.DB {
	db, err := database.CreateDB(opts.DbConnectionString, 10*time.Second)
	if err != nil {
		log.Fatal("db creation error")
	}

	if err = prepareRuntimeDatabase(
		context.Background(),
		db,
		opts.Vault.Enabled || opts.A3.WitnessEnabled,
	); err != nil {
		if opts.Vault.Enabled {
			log.Fatal("database schema gate failed")
		}
		log.Fatal("db migration error")
	}

	return db
}

func prepareRuntimeDatabase(
	ctx context.Context,
	db *sql.DB,
	secure bool,
) error {
	if secure {
		return database.RequireCurrentSchema(ctx, db)
	}
	return database.Migrate(ctx, db)
}

func initMigrationDb() *sql.DB {
	if opts.MigrationDbConnectionString == "" {
		log.Fatal("migration database connection missing")
	}
	db, err := database.CreateDB(
		opts.MigrationDbConnectionString,
		10*time.Second,
	)
	if err != nil {
		log.Fatal("migration database creation error")
	}
	if err = database.Migrate(context.Background(), db); err != nil {
		log.Fatal("db migration error")
	}
	return db
}

func legacyRetirementPreflightModeValid(config options.Options) bool {
	return config.PreflightLegacyRetirement &&
		config.MigrationDbConnectionString != "" &&
		config.DbConnectionString == "" &&
		config.CreateMigration == "" &&
		!config.MigrateOnly &&
		!config.Api.Enabled &&
		!config.Xmtp.ListenerEnabled &&
		!config.Apns.Enabled &&
		!config.Fcm.Enabled &&
		!config.HttpDelivery.Enabled &&
		!config.Vault.Enabled &&
		!config.A9.Enabled &&
		!config.A10.Enabled &&
		!config.A3.AssociationEnabled &&
		!config.A3.WitnessEnabled &&
		!config.Incident.Enabled &&
		!legacyRetirementPreflightRuntimeCredentialPresent(config)
}

type legacyRetirementPreflightRunner func(
	context.Context,
	string,
	time.Duration,
) (string, bool)

func runLegacyRetirementPreflightMode(
	ctx context.Context,
	config options.Options,
	stdout io.Writer,
	stderr io.Writer,
	run legacyRetirementPreflightRunner,
) bool {
	if ctx == nil ||
		!legacyRetirementPreflightModeValid(config) ||
		stdout == nil ||
		stderr == nil ||
		run == nil {
		writeLegacyRetirementPreflightFailure(stderr)
		return false
	}

	preflightCtx, cancel := context.WithTimeout(
		ctx,
		legacyRetirementPreflightTimeout,
	)
	defer cancel()

	output, passed := run(
		preflightCtx,
		config.MigrationDbConnectionString,
		legacyRetirementPreflightDBWait,
	)
	if !passed {
		writeLegacyRetirementPreflightFailure(stderr)
		return false
	}
	if _, err := io.WriteString(stdout, output); err != nil {
		writeLegacyRetirementPreflightFailure(stderr)
		return false
	}
	return true
}

func legacyRetirementPreflightRequested(args []string) bool {
	return legacyRetirementPreflightLongOptionPresent(
		args,
		"--preflight-legacy-retirement",
	)
}

func legacyRetirementPreflightMigrationDSNOnCLI(args []string) bool {
	return legacyRetirementPreflightLongOptionPresent(
		args,
		"--migration-db-connection-string",
	)
}

func legacyRetirementPreflightLongOptionPresent(
	args []string,
	option string,
) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == option || strings.HasPrefix(arg, option+"=") {
			return true
		}
	}
	return false
}

func writeLegacyRetirementPreflightFailure(stderr io.Writer) {
	if stderr != nil {
		_, _ = io.WriteString(
			stderr,
			database.LegacyRetirementPreflightFailureOutput,
		)
	}
}

func legacyRetirementPreflightRuntimeCredentialPresent(
	config options.Options,
) bool {
	return config.Apns.P8Certificate != "" ||
		config.Apns.P8CertificateBase64 != "" ||
		config.Apns.P8CertificateFilePath != "" ||
		config.Apns.KeyId != "" ||
		config.Apns.TeamId != "" ||
		config.Apns.Topic != "" ||
		config.Fcm.CredentialsJson != "" ||
		config.Fcm.ProjectId != "" ||
		config.HttpDelivery.Address != "" ||
		config.HttpDelivery.AuthHeader != "" ||
		config.Vault.MasterKeysJSON != "" ||
		config.Vault.LookupKey != "" ||
		config.Vault.AuthorityPublicKeysJSON != "" ||
		config.Vault.APIBearerToken != "" ||
		config.A9.HasTrustMaterial() ||
		config.A10.HasTrustMaterial() ||
		config.A3.HasTrustMaterial() ||
		config.Incident.ActorCredentialsJSON != "" ||
		config.Incident.OversightWebhookURL != "" ||
		config.Incident.OversightWebhookBearer != ""
}

func createMigration() error {
	files, err := database.CreateMigrationFiles(opts.CreateMigration)
	if err != nil {
		return err
	}
	for _, file := range files {
		fmt.Printf("created migration %s (%s)\n", file.Name, file.Path)
	}
	return nil
}

func shortGitCommit() string {
	val := GitCommit
	if len(val) >= 7 {
		val = val[:7]
	}
	return val
}

func shortXMTPGoClientVersion() string {
	return strings.Split(XMTPGoClientVersion, "-")[0]
}
