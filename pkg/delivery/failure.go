package delivery

import "errors"

// IsPermanentFailure reports whether a provider error will fail identically
// on retry for this recipient. Durable dispatch records such recipients as
// rejected; every other error stays retryable within the bounded window.
func IsPermanentFailure(err error) bool {
	var apnsRejection *ApnsRejection
	if errors.As(err, &apnsRejection) {
		return apnsRejection.Permanent
	}
	var fcmRejection *FcmRejection
	return errors.As(err, &fcmRejection)
}
