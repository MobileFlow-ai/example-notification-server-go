package installations

import (
	"context"
	"database/sql"
	"time"

	database "github.com/xmtp/example-notification-server-go/pkg/db"
	"github.com/xmtp/example-notification-server-go/pkg/db/queries"
	"github.com/xmtp/example-notification-server-go/pkg/interfaces"
	"go.uber.org/zap"
)

type DefaultInstallationService struct {
	logger  *zap.Logger
	db      *sql.DB
	queries *queries.Queries
}

func NewInstallationsService(logger *zap.Logger, db *sql.DB) *DefaultInstallationService {
	return &DefaultInstallationService{
		logger:  logger.Named("installations"),
		db:      db,
		queries: queries.New(db),
	}
}

func (s DefaultInstallationService) Register(
	ctx context.Context,
	installation interfaces.Installation,
) (*interfaces.RegisterResponse, error) {
	updatedAt := installation.DeliveryMechanism.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}

	return database.RunInTxResult(ctx, s.db, func(qtx *queries.Queries) (*interfaces.RegisterResponse, error) {
		if err := qtx.UpsertInstallation(ctx, queries.UpsertInstallationParams{
			ID:            installation.Id,
			PayloadFormat: int16(installation.PayloadFormat),
		}); err != nil {
			return nil, err
		}

		err := qtx.UpsertDeviceDeliveryMechanism(ctx, queries.UpsertDeviceDeliveryMechanismParams{
			InstallationID: installation.Id,
			Kind:           string(installation.DeliveryMechanism.Kind),
			Token:          installation.DeliveryMechanism.Token,
			UpdatedAt:      updatedAt,
		})
		if err != nil {
			return nil, err
		}

		return &interfaces.RegisterResponse{
			InstallationId: installation.Id,
			ValidUntil:     getExpiry(updatedAt),
		}, nil
	})
}

func (s DefaultInstallationService) Delete(ctx context.Context, installationID string) error {
	return database.RunInTx(ctx, s.db, func(qtx *queries.Queries) error {
		err := qtx.SoftDeleteInstallation(ctx, queries.SoftDeleteInstallationParams{
			ID:        installationID,
			DeletedAt: sql.NullTime{Time: time.Now(), Valid: true},
		})
		if err != nil {
			return err
		}

		return qtx.DeactivateInstallationSubscriptions(ctx, installationID)
	})
}

func (s DefaultInstallationService) GetInstallations(
	ctx context.Context,
	installationIDs []string,
) ([]interfaces.Installation, error) {
	if len(installationIDs) == 0 {
		return []interfaces.Installation{}, nil
	}

	results, err := s.queries.GetLatestInstallations(ctx, installationIDs)
	if err != nil {
		return nil, err
	}

	out := make([]interfaces.Installation, 0, len(results))
	for _, result := range results {
		out = append(out, interfaces.Installation{
			Id: result.InstallationID,
			DeliveryMechanism: interfaces.DeliveryMechanism{
				Kind:                interfaces.DeliveryMechanismKind(result.Kind),
				Token:               result.Token,
				UpdatedAt:           result.UpdatedAt,
				RegistrationVersion: result.RegistrationVersion,
			},
			PayloadFormat: interfaces.PayloadFormat(result.PayloadFormat),
		})
	}
	return out, nil
}

func getExpiry(createdAt time.Time) time.Time {
	return createdAt
}

// InvalidateDeliveryToken uses both the captured registration version and the
// provider timestamp. A delayed failure cannot retire a renewed same token or
// its replacement. Keeping the invalid latest row prevents stale-token fallback.
func (s DefaultInstallationService) InvalidateDeliveryToken(ctx context.Context, installation interfaces.Installation, invalidBefore time.Time) error {
	mechanism := installation.DeliveryMechanism
	if installation.Id == "" || mechanism.Token == "" || mechanism.UpdatedAt.IsZero() || mechanism.RegistrationVersion <= 0 {
		return nil
	}
	return s.queries.InvalidateDeliveryToken(ctx, queries.InvalidateDeliveryTokenParams{
		InstallationID:              installation.Id,
		Kind:                        string(mechanism.Kind),
		Token:                       mechanism.Token,
		ExpectedUpdatedAt:           mechanism.UpdatedAt,
		ExpectedRegistrationVersion: mechanism.RegistrationVersion,
		InvalidBefore:               sql.NullTime{Time: invalidBefore, Valid: !invalidBefore.IsZero()},
	})
}
