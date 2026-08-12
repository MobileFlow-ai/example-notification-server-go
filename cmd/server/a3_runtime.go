package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/xmtp/example-notification-server-go/pkg/a3trust"
	"github.com/xmtp/example-notification-server-go/pkg/a9trust"
	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	identityv1 "github.com/xmtp/xmtpd/pkg/proto/identity/api/v1"
	validationv1 "github.com/xmtp/xmtpd/pkg/proto/mls_validation/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var errA3RuntimeConfiguration = errors.New("a3 runtime configuration invalid")

const maxA3SequencerKeysetBytes = 8 * 1024
const a3DevIdentityGRPCAddress = "grpc.dev.xmtp.network:443"

type a3Runtime struct {
	association *a3trust.AssociationHandler
	witness     *a3trust.WitnessHandler
	connections []*grpc.ClientConn
}

func (runtime *a3Runtime) Close() error {
	if runtime == nil {
		return nil
	}
	var result error
	if runtime.association != nil {
		runtime.association.Close()
	}
	if runtime.witness != nil {
		runtime.witness.Close()
	}
	for _, connection := range runtime.connections {
		if connection != nil {
			result = errors.Join(result, connection.Close())
		}
	}
	return result
}

type a3RuntimeDependencies struct {
	identityClient   identityUpdatesClientForRuntime
	validationClient validationClientForRuntime
	clock            func() time.Time
}

type identityUpdatesClientForRuntime interface {
	GetIdentityUpdates(context.Context, *identityv1.GetIdentityUpdatesRequest, ...grpc.CallOption) (*identityv1.GetIdentityUpdatesResponse, error)
}

type validationClientForRuntime interface {
	GetAssociationState(context.Context, *validationv1.GetAssociationStateRequest, ...grpc.CallOption) (*validationv1.GetAssociationStateResponse, error)
}

func initializeA3Runtime(
	ctx context.Context,
	config options.A3Options,
	environment string,
	db *sql.DB,
) (*a3Runtime, error) {
	return initializeA3RuntimeWithDependencies(
		ctx,
		config,
		environment,
		db,
		a3RuntimeDependencies{},
	)
}

func initializeA3RuntimeWithDependencies(
	ctx context.Context,
	config options.A3Options,
	environment string,
	db *sql.DB,
	dependencies a3RuntimeDependencies,
) (*a3Runtime, error) {
	if ctx == nil || ctx.Err() != nil ||
		(!config.AssociationEnabled && !config.WitnessEnabled) {
		return nil, errA3RuntimeConfiguration
	}
	runtime := &a3Runtime{}
	fail := func() (*a3Runtime, error) {
		_ = runtime.Close()
		return nil, errA3RuntimeConfiguration
	}
	var (
		witnessStore         *database.A3WitnessStore
		witnessPrivateKey    ed25519.PrivateKey
		witnessPublicKey     ed25519.PublicKey
		witnessSequencerKeys map[string]ed25519.PublicKey
	)
	if config.WitnessEnabled {
		if db == nil {
			return fail()
		}
		witnessStore = database.NewA3WitnessStore(db)
		barrierCtx, barrierCancel := context.WithTimeout(ctx, 10*time.Second)
		barrierErr := witnessStore.RequireActivationBarrier(barrierCtx)
		barrierCancel()
		if barrierErr != nil {
			return fail()
		}
		seed, err := readA3WitnessSeed(config.WitnessSeedFilePath)
		if err != nil {
			return fail()
		}
		witnessPrivateKey = ed25519.NewKeyFromSeed(seed)
		clear(seed)
		defer clear(witnessPrivateKey)
		witnessPublicKey = witnessPrivateKey.Public().(ed25519.PublicKey)
		continuityCtx, continuityCancel := context.WithTimeout(ctx, 10*time.Second)
		continuityErr := witnessStore.RequireKeyContinuity(
			continuityCtx,
			environment,
			witnessPublicKey,
		)
		continuityCancel()
		if continuityErr != nil {
			return fail()
		}
		witnessSequencerKeys, err = parseA3SequencerKeys(
			config.WitnessSequencerPublicKeysJSON,
		)
		if err != nil {
			return fail()
		}
		for _, key := range witnessSequencerKeys {
			defer clear(key)
		}
	}
	if config.AssociationEnabled {
		if !validA3IdentityTarget(
			environment,
			config.IdentityGRPCAddress,
		) || !validA3GRPCTarget(
			config.ValidationGRPCAddress,
			!config.ValidationAllowPlaintextLoopback,
		) {
			return fail()
		}
		identityClient := dependencies.identityClient
		validationClient := dependencies.validationClient
		if (identityClient == nil) != (validationClient == nil) {
			return fail()
		}
		if identityClient == nil {
			identityConnection, err := newA3GRPCConnection(
				config.IdentityGRPCAddress,
				true,
			)
			if err != nil {
				return fail()
			}
			runtime.connections = append(runtime.connections, identityConnection)
			validationConnection, err := newA3GRPCConnection(
				config.ValidationGRPCAddress,
				!config.ValidationAllowPlaintextLoopback,
			)
			if err != nil {
				return fail()
			}
			runtime.connections = append(runtime.connections, validationConnection)
			identityClient = identityv1.NewIdentityApiClient(identityConnection)
			validationClient = validationv1.NewValidationApiClient(validationConnection)
		}
		source, err := a3trust.NewGRPCIdentityHistorySource(
			identityClient,
			config.AssociationMaxPages,
			config.AssociationMaxPageUpdates,
			config.AssociationMaxUpdates,
			config.AssociationMaxUpdateBytes,
			config.AssociationMaxHistoryBytes,
		)
		if err != nil {
			return fail()
		}
		validator, err := a3trust.NewGRPCAssociationValidator(validationClient)
		if err != nil {
			return fail()
		}
		reader, err := a3trust.NewValidatedAssociationReader(
			source,
			validator,
			dependencies.clock,
			time.Duration(config.AssociationMaximumClockSkewSec)*time.Second,
			config.AssociationMaxUpdates,
			config.AssociationMaxUpdateBytes,
			config.AssociationMaxHistoryBytes,
			config.AssociationMaxValidationBytes,
		)
		if err != nil {
			return fail()
		}
		runtime.association, err = a3trust.NewAssociationHandler(a3trust.AssociationOptions{
			Enabled: true, Environment: environment,
			BearerToken: config.AssociationBearerToken, Reader: reader,
			MaxConcurrency: config.AssociationMaxConcurrency,
			RatePerSecond:  config.AssociationRatePerSecond,
			RateBurst:      config.AssociationRateBurst,
			RequestTimeout: time.Duration(config.AssociationRequestTimeoutSeconds) * time.Second,
			Clock:          dependencies.clock,
		})
		if err != nil {
			return fail()
		}
	}
	if config.WitnessEnabled {
		var err error
		runtime.witness, err = a3trust.NewWitnessHandler(a3trust.WitnessOptions{
			Enabled: true, Environment: environment,
			BearerToken:      config.WitnessBearerToken,
			Store:            witnessStore,
			PrivateKey:       witnessPrivateKey,
			KeyID:            a3trust.WitnessKeyID(witnessPublicKey),
			MaxConcurrency:   config.WitnessMaxConcurrency,
			RatePerSecond:    config.WitnessRatePerSecond,
			RateBurst:        config.WitnessRateBurst,
			RequestTimeout:   time.Duration(config.WitnessRequestTimeoutSeconds) * time.Second,
			Clock:            dependencies.clock,
			MaximumClockSkew: time.Duration(config.WitnessMaximumClockSkewSec) * time.Second,
			MaximumHeadAge:   time.Duration(config.WitnessMaximumAgeSeconds) * time.Second,
			SequencerKeys:    witnessSequencerKeys,
		})
		if err != nil {
			return fail()
		}
	}
	return runtime, nil
}

func newA3GRPCConnection(address string, useTLS bool) (*grpc.ClientConn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, errA3RuntimeConfiguration
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return nil, errA3RuntimeConfiguration
	}
	var transport credentials.TransportCredentials
	if useTLS {
		transport = credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: host,
		})
	} else {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, errA3RuntimeConfiguration
		}
		transport = insecure.NewCredentials()
	}
	return grpc.NewClient(
		address,
		grpc.WithTransportCredentials(transport),
		grpc.WithNoProxy(),
		grpc.WithDisableRetry(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(4*1024*1024),
			grpc.MaxCallSendMsgSize(4*1024*1024),
		),
	)
}

func validA3IdentityTarget(environment, address string) bool {
	return environment == "dev" && address == a3DevIdentityGRPCAddress
}

func validA3GRPCTarget(address string, useTLS bool) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return false
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return false
	}
	if useTLS {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readA3WitnessSeed(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errA3RuntimeConfiguration
	}
	parent := filepath.Dir(path)
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) ||
		!validA3SeedAncestors(parent) {
		return nil, errA3RuntimeConfiguration
	}
	parentBefore, err := os.Lstat(parent)
	if err != nil || !validA3SeedParentInfo(parentBefore) {
		return nil, errA3RuntimeConfiguration
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, errA3RuntimeConfiguration
	}
	defer func() { _ = root.Close() }()
	openedParent, err := root.Stat(".")
	parentAfter, pathErr := os.Lstat(parent)
	if err != nil || pathErr != nil ||
		!validA3SeedParentInfo(openedParent) ||
		!validA3SeedParentInfo(parentAfter) ||
		!os.SameFile(parentBefore, openedParent) ||
		!os.SameFile(openedParent, parentAfter) {
		return nil, errA3RuntimeConfiguration
	}
	before, err := root.Lstat(name)
	if err != nil || !validA3WitnessSeedInfo(before) {
		return nil, errA3RuntimeConfiguration
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errA3RuntimeConfiguration
	}
	opened, err := file.Stat()
	if err != nil || !validA3WitnessSeedInfo(opened) || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errA3RuntimeConfiguration
	}
	afterOpen, err := root.Lstat(name)
	if err != nil || !validA3WitnessSeedInfo(afterOpen) ||
		!os.SameFile(opened, afterOpen) {
		_ = file.Close()
		return nil, errA3RuntimeConfiguration
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, ed25519.SeedSize+1))
	finalOpened, statErr := file.Stat()
	afterRead, pathErr := root.Lstat(name)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || pathErr != nil || closeErr != nil ||
		len(raw) != ed25519.SeedSize || !validA3WitnessSeedInfo(finalOpened) ||
		!validA3WitnessSeedInfo(afterRead) || !os.SameFile(opened, finalOpened) ||
		!os.SameFile(finalOpened, afterRead) || allZeroBytes(raw) {
		clear(raw)
		return nil, errA3RuntimeConfiguration
	}
	return raw, nil
}

func validA3SeedAncestors(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err != nil || info == nil || !info.IsDir() ||
			info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		parent := filepath.Dir(current)
		if parent == current {
			return true
		}
		current = parent
	}
}

func validA3SeedParentInfo(info os.FileInfo) bool {
	return info != nil && info.IsDir() &&
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 &&
		info.Mode().Perm()&0o022 == 0
}

func validA3WitnessSeedInfo(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() || info.Size() != ed25519.SeedSize ||
		info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	permissions := info.Mode().Perm()
	return permissions&0o400 != 0 && permissions&0o111 == 0 && permissions&0o077 == 0
}

func parseA3SequencerKeys(raw string) (map[string]ed25519.PublicKey, error) {
	if len(raw) == 0 || len(raw) > maxA3SequencerKeysetBytes {
		return nil, errA3RuntimeConfiguration
	}
	parsed, err := a9trust.ParseStrictJSON([]byte(raw))
	object, ok := parsed.(map[string]any)
	if err != nil || !ok || len(object) < 1 || len(object) > 8 {
		return nil, errA3RuntimeConfiguration
	}
	result := make(map[string]ed25519.PublicKey, len(object))
	clearResult := func() {
		for _, key := range result {
			clear(key)
		}
	}
	for keyID, rawValue := range object {
		value, valueOK := rawValue.(string)
		decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(value)
		if !valueOK || decodeErr != nil || len(decoded) != ed25519.PublicKeySize ||
			allZeroBytes(decoded) ||
			base64.StdEncoding.EncodeToString(decoded) != value {
			clear(decoded)
			clearResult()
			return nil, errA3RuntimeConfiguration
		}
		publicKey := ed25519.PublicKey(decoded)
		if a3trust.WitnessKeyID(publicKey) != keyID {
			clear(decoded)
			clearResult()
			return nil, errA3RuntimeConfiguration
		}
		result[keyID] = publicKey
	}
	return result, nil
}

func allZeroBytes(value []byte) bool {
	var combined byte
	for index := range value {
		combined |= value[index]
	}
	return combined == 0
}
