package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xmtp/example-notification-server-go/pkg/options"
	"golang.org/x/sys/unix"
)

type rejectingA9Writer struct{}

func (rejectingA9Writer) Write([]byte) (int, error) {
	return 0, errors.New("write rejected")
}

type partialRejectingA9Writer struct {
	observed bytes.Buffer
}

type a9ModeOverrideFileInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (info a9ModeOverrideFileInfo) Mode() os.FileMode {
	return info.mode
}

func (writer *partialRejectingA9Writer) Write(value []byte) (int, error) {
	written := 5
	if len(value) < written {
		written = len(value)
	}
	_, _ = writer.observed.Write(value[:written])
	return written, errors.New("partial write rejected")
}

func TestA9ProvisioningCreatesOneRestrictedFileFromStdin(t *testing.T) {
	path := filepath.Join(a9TestDirectory(t), "topic-keys.json")
	config := options.Options{ProvisionA9Material: a9TopicCommitmentKeysMaterial}
	config.A9.TopicCommitmentKeysFilePath = path
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	require.True(t, runA9MaterialMode(
		config,
		strings.NewReader("fixture-material\n"),
		&stdout,
		&stderr,
	))
	require.Equal(
		t,
		a9ProvisionPassOutput+a9TopicCommitmentKeysVariable+"\n",
		stdout.String(),
	)
	require.Empty(t, stderr.String())
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	require.True(t, a9FileOwnedByCurrentProcess(info))
	material, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("fixture-material\n"), material)
}

func TestA9ProvisioningRefusesOverwriteAndSymlink(t *testing.T) {
	directory := a9TestDirectory(t)
	existing := filepath.Join(directory, "existing")
	require.NoError(t, os.WriteFile(existing, []byte("keep"), 0o600))
	symlink := filepath.Join(directory, "symlink")
	require.NoError(t, os.Symlink(existing, symlink))

	for name, path := range map[string]string{
		"existing": existing,
		"symlink":  symlink,
	} {
		t.Run(name, func(t *testing.T) {
			config := options.Options{
				ProvisionA9Material: a9TLSPrivateKeyMaterial,
			}
			config.A9.TLSPrivateKeyFilePath = path
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			require.False(t, runA9MaterialMode(
				config,
				strings.NewReader("replacement"),
				&stdout,
				&stderr,
			))
			require.Empty(t, stdout.String())
			require.Equal(t, a9MaterialFailureOutput, stderr.String())
			material, err := os.ReadFile(existing)
			require.NoError(t, err)
			require.Equal(t, []byte("keep"), material)
		})
	}
}

func TestA9ProvisioningAndPreflightRejectFIFOWithoutBlocking(t *testing.T) {
	for _, operation := range []struct {
		name string
		run  func(string) error
	}{
		{
			name: "provision",
			run: func(path string) error {
				_, err := provisionRestrictedA9File(
					strings.NewReader("material"),
					path,
					a9MaterialMaxBytes,
				)
				return err
			},
		},
		{
			name: "preflight",
			run: func(path string) error {
				_, err := openCheckedA9RuntimeFile(
					path,
					a9RuntimeTLSPrivateKey,
					a9MaterialMaxBytes,
				)
				return err
			},
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			path := filepath.Join(a9TestDirectory(t), "fifo")
			require.NoError(t, unix.Mkfifo(path, 0o600))
			done := make(chan error, 1)
			go func() { done <- operation.run(path) }()
			select {
			case err := <-done:
				require.ErrorIs(t, err, errA9MaterialRejected)
			case <-time.After(time.Second):
				t.Fatal("special-file rejection blocked")
			}
		})
	}
}

func TestA9ProvisioningRejectsSymlinkedParent(t *testing.T) {
	directory := a9TestDirectory(t)
	realParent := filepath.Join(directory, "real")
	require.NoError(t, os.Mkdir(realParent, 0o700))
	linkedParent := filepath.Join(directory, "linked")
	require.NoError(t, os.Symlink(realParent, linkedParent))
	path := filepath.Join(linkedParent, "material")
	config := options.Options{
		ProvisionA9Material: a9TLSPrivateKeyMaterial,
	}
	config.A9.TLSPrivateKeyFilePath = path
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	require.False(t, runA9MaterialMode(
		config,
		strings.NewReader("material"),
		&stdout,
		&stderr,
	))
	require.Empty(t, stdout.String())
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
	_, err := os.Lstat(filepath.Join(realParent, "material"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestA9ProvisioningRejectsSymlinkedAncestor(t *testing.T) {
	directory := a9TestDirectory(t)
	realAncestor := filepath.Join(directory, "real")
	realParent := filepath.Join(realAncestor, "parent")
	require.NoError(t, os.MkdirAll(realParent, 0o700))
	linkedAncestor := filepath.Join(directory, "linked")
	require.NoError(t, os.Symlink(realAncestor, linkedAncestor))
	path := filepath.Join(linkedAncestor, "parent", "material")
	config := options.Options{
		ProvisionA9Material: a9TLSPrivateKeyMaterial,
	}
	config.A9.TLSPrivateKeyFilePath = path
	var stderr bytes.Buffer
	require.False(t, runA9MaterialMode(
		config,
		strings.NewReader("material"),
		io.Discard,
		&stderr,
	))
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
	_, err := os.Lstat(filepath.Join(realParent, "material"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestA9ProvisioningParentSwapFailsWithoutDeletingReplacement(
	t *testing.T,
) {
	directory := a9TestDirectory(t)
	parent := filepath.Join(directory, "parent")
	movedParent := filepath.Join(directory, "moved-parent")
	require.NoError(t, os.Mkdir(parent, 0o700))
	path := filepath.Join(parent, "material")
	a9MaterialTestHook = func(stage string) {
		if stage != a9MaterialHookProvisionParentOpened {
			return
		}
		require.NoError(t, os.Rename(parent, movedParent))
		require.NoError(t, os.Mkdir(parent, 0o700))
		require.NoError(t, os.WriteFile(path, []byte("replacement"), 0o600))
	}
	t.Cleanup(func() { a9MaterialTestHook = nil })

	config := options.Options{
		ProvisionA9Material: a9TLSPrivateKeyMaterial,
	}
	config.A9.TLSPrivateKeyFilePath = path
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	require.False(t, runA9MaterialMode(
		config,
		strings.NewReader("secret-material"),
		&stdout,
		&stderr,
	))
	require.Empty(t, stdout.String())
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
	replacement, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("replacement"), replacement)
	created, err := os.ReadFile(filepath.Join(movedParent, "material"))
	require.NoError(t, err)
	require.Equal(t, []byte("secret-material"), created)
}

func TestA9ProvisioningFinalSwapFailsWithoutDeletingReplacement(
	t *testing.T,
) {
	directory := a9TestDirectory(t)
	path := filepath.Join(directory, "material")
	moved := filepath.Join(directory, "created-material")
	a9MaterialTestHook = func(stage string) {
		if stage != a9MaterialHookProvisionFileSynced {
			return
		}
		require.NoError(t, os.Rename(path, moved))
		require.NoError(t, os.WriteFile(path, []byte("replacement"), 0o600))
	}
	t.Cleanup(func() { a9MaterialTestHook = nil })

	config := options.Options{
		ProvisionA9Material: a9TLSPrivateKeyMaterial,
	}
	config.A9.TLSPrivateKeyFilePath = path
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	require.False(t, runA9MaterialMode(
		config,
		strings.NewReader("secret-material"),
		&stdout,
		&stderr,
	))
	require.Empty(t, stdout.String())
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
	replacement, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("replacement"), replacement)
	created, err := os.ReadFile(moved)
	require.NoError(t, err)
	require.Equal(t, []byte("secret-material"), created)
}

func TestA9ProvisioningRejectsEmptyOversizedAndOutputFailure(t *testing.T) {
	testCases := []struct {
		name         string
		stdin        io.Reader
		stdout       io.Writer
		fileRetained bool
	}{
		{name: "empty", stdin: strings.NewReader(""), stdout: io.Discard},
		{
			name:   "oversized",
			stdin:  io.LimitReader(zeroA9Reader{}, a9MaterialMaxBytes+1),
			stdout: io.Discard,
		},
		{
			name:         "output failure",
			stdin:        strings.NewReader("material"),
			stdout:       rejectingA9Writer{},
			fileRetained: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(a9TestDirectory(t), "material")
			config := options.Options{
				ProvisionA9Material: a9TLSCertificateMaterial,
			}
			config.A9.TLSCertificateFilePath = path
			var stderr bytes.Buffer
			require.False(t, runA9MaterialMode(
				config,
				testCase.stdin,
				testCase.stdout,
				&stderr,
			))
			require.Equal(t, a9MaterialFailureOutput, stderr.String())
			if testCase.fileRetained {
				require.True(t, restrictedA9FileValid(path))
				material, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, []byte("material"), material)
				var retryStderr bytes.Buffer
				require.False(t, runA9MaterialMode(
					config,
					strings.NewReader("replacement"),
					io.Discard,
					&retryStderr,
				))
				require.Equal(
					t,
					a9MaterialFailureOutput,
					retryStderr.String(),
				)
				material, err = os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, []byte("material"), material)
			} else {
				_, err := os.Lstat(path)
				require.ErrorIs(t, err, os.ErrNotExist)
			}
		})
	}
}

func TestA9ProvisioningPartialAcknowledgementIsFailureAndQuarantine(
	t *testing.T,
) {
	path := filepath.Join(a9TestDirectory(t), "material")
	config := options.Options{ProvisionA9Material: a9TLSCertificateMaterial}
	config.A9.TLSCertificateFilePath = path
	stdout := &partialRejectingA9Writer{}
	var stderr bytes.Buffer

	require.False(t, runA9MaterialMode(
		config,
		strings.NewReader("material"),
		stdout,
		&stderr,
	))
	require.NotEmpty(t, stdout.observed.String())
	require.NotEqual(
		t,
		a9ProvisionPassOutput+a9TLSCertificateVariable+"\n",
		stdout.observed.String(),
	)
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
	require.True(t, restrictedA9FileValid(path))
}

func TestA9ProvisioningEnforcesExactMaterialSizeBounds(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		material string
		maxBytes int64
	}{
		{
			name:     "topic keys",
			material: a9TopicCommitmentKeysMaterial,
			maxBytes: maxA9TopicKeySourceBytes,
		},
		{
			name:     "tls certificate",
			material: a9TLSCertificateMaterial,
			maxBytes: a9MaterialMaxBytes,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			exactPath := filepath.Join(a9TestDirectory(t), "exact")
			exactConfig := options.Options{
				ProvisionA9Material: testCase.material,
			}
			if testCase.material == a9TopicCommitmentKeysMaterial {
				exactConfig.A9.TopicCommitmentKeysFilePath = exactPath
			} else {
				exactConfig.A9.TLSCertificateFilePath = exactPath
			}
			var exactStderr bytes.Buffer
			require.True(t, runA9MaterialMode(
				exactConfig,
				io.LimitReader(zeroA9Reader{}, testCase.maxBytes),
				io.Discard,
				&exactStderr,
			))
			require.Empty(t, exactStderr.String())
			info, err := os.Lstat(exactPath)
			require.NoError(t, err)
			require.Equal(t, testCase.maxBytes, info.Size())

			oversizedPath := filepath.Join(a9TestDirectory(t), "oversized")
			oversizedConfig := exactConfig
			if testCase.material == a9TopicCommitmentKeysMaterial {
				oversizedConfig.A9.TopicCommitmentKeysFilePath = oversizedPath
			} else {
				oversizedConfig.A9.TLSCertificateFilePath = oversizedPath
			}
			var oversizedStderr bytes.Buffer
			require.False(t, runA9MaterialMode(
				oversizedConfig,
				io.LimitReader(zeroA9Reader{}, testCase.maxBytes+1),
				io.Discard,
				&oversizedStderr,
			))
			require.Equal(
				t,
				a9MaterialFailureOutput,
				oversizedStderr.String(),
			)
			_, err = os.Lstat(oversizedPath)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestA9ProvisioningPanicAfterCreateRetainsRestrictedFile(t *testing.T) {
	path := filepath.Join(a9TestDirectory(t), "material")
	a9MaterialTestHook = func(stage string) {
		if stage == a9MaterialHookProvisionFileSynced {
			panic("fixture-secret-must-not-escape")
		}
	}
	t.Cleanup(func() { a9MaterialTestHook = nil })
	config := options.Options{
		ProvisionA9Material: a9TLSPrivateKeyMaterial,
	}
	config.A9.TLSPrivateKeyFilePath = path
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	completed := runWithA9MaterialPanicBoundary(func() {
		require.False(t, runA9MaterialMode(
			config,
			strings.NewReader("secret-material"),
			&stdout,
			&stderr,
		))
	}, &stderr)
	require.False(t, completed)
	require.Empty(t, stdout.String())
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.True(t, provisionedA9FileInfoValid(info, a9MaterialMaxBytes))
	material, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, []byte("secret-material"), material)
}

type zeroA9Reader struct{}

func (zeroA9Reader) Read(target []byte) (int, error) {
	for index := range target {
		target[index] = 0
	}
	return len(target), nil
}

func TestA9FilePreflightUsesExactRuntimeContractAndMetadataOnly(t *testing.T) {
	config := validA9RuntimeOptions(t)
	config.PreflightA9RuntimeFiles = true
	config.A9.TopicCommitmentKeysFilePath = writeRestrictedA9Fixture(t, "topic")
	config.A9.TLSCertificateFilePath = writeRestrictedA9Fixture(t, "certificate")
	config.A9.TLSPrivateKeyFilePath = writeRestrictedA9Fixture(t, "private-key")
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	require.True(t, runA9MaterialMode(
		config,
		strings.NewReader("unused"),
		&stdout,
		&stderr,
	))
	require.Equal(
		t,
		a9PreflightPassOutput+
			a9TopicCommitmentKeysVariable+"\n"+
			a9TLSCertificateVariable+"\n"+
			a9TLSPrivateKeyVariable+"\n",
		stdout.String(),
	)
	require.Empty(t, stderr.String())
	require.NotContains(t, stdout.String(), "topic")
	require.NotContains(t, stdout.String(), "certificate")
	require.NotContains(t, stdout.String(), "private-key")
}

func TestA9FilePreflightAcceptsRuntimeSafeReadOnlyModes(t *testing.T) {
	config := validA9RuntimeOptions(t)
	config.PreflightA9RuntimeFiles = true
	config.A9.TopicCommitmentKeysFilePath = writeRestrictedA9Fixture(t, "topic")
	config.A9.TLSCertificateFilePath = writeRestrictedA9Fixture(t, "certificate")
	config.A9.TLSPrivateKeyFilePath = writeRestrictedA9Fixture(t, "private-key")
	require.NoError(t, os.Chmod(config.A9.TopicCommitmentKeysFilePath, 0o400))
	require.NoError(t, os.Chmod(config.A9.TLSCertificateFilePath, 0o444))
	require.NoError(t, os.Chmod(config.A9.TLSPrivateKeyFilePath, 0o400))
	var stderr bytes.Buffer
	require.True(t, runA9MaterialMode(
		config,
		strings.NewReader("unused"),
		io.Discard,
		&stderr,
	))
	require.Empty(t, stderr.String())
}

func TestA9FilePreflightFailsClosedOnContractMetadataAndAliasing(t *testing.T) {
	for name, mutate := range map[string]func(*options.Options){
		"runtime contract": func(config *options.Options) {
			config.Xmtp.ListenerType = "v3"
		},
		"missing": func(config *options.Options) {
			config.A9.TLSCertificateFilePath = filepath.Join(
				a9TestDirectory(t),
				"missing",
			)
		},
		"permissive": func(config *options.Options) {
			require.NoError(t, os.Chmod(config.A9.TLSPrivateKeyFilePath, 0o640))
		},
		"same file": func(config *options.Options) {
			config.A9.TLSPrivateKeyFilePath = config.A9.TLSCertificateFilePath
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := validA9RuntimeOptions(t)
			config.PreflightA9RuntimeFiles = true
			config.A9.TopicCommitmentKeysFilePath =
				writeRestrictedA9Fixture(t, "topic")
			config.A9.TLSCertificateFilePath =
				writeRestrictedA9Fixture(t, "certificate")
			config.A9.TLSPrivateKeyFilePath =
				writeRestrictedA9Fixture(t, "private-key")
			mutate(&config)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			require.False(t, runA9MaterialMode(
				config,
				strings.NewReader("unused"),
				&stdout,
				&stderr,
			))
			require.Empty(t, stdout.String())
			require.Equal(t, a9MaterialFailureOutput, stderr.String())
		})
	}
}

func TestA9FilePreflightRejectsSpecialBitsHardlinksAndWritableParent(
	t *testing.T,
) {
	for _, testCase := range []struct {
		name   string
		mutate func(*testing.T, *options.Options)
	}{
		{
			name: "special mode bits",
			mutate: func(t *testing.T, config *options.Options) {
				require.NoError(t, unix.Chmod(
					config.A9.TLSPrivateKeyFilePath,
					unix.S_IRUSR|unix.S_IWUSR|unix.S_ISUID,
				))
				info, err := os.Lstat(config.A9.TLSPrivateKeyFilePath)
				require.NoError(t, err)
				if info.Mode()&os.ModeSetuid == 0 {
					t.Skip("filesystem cleared the setuid fixture bit")
				}
			},
		},
		{
			name: "hardlink alias",
			mutate: func(t *testing.T, config *options.Options) {
				require.NoError(t, os.Remove(config.A9.TLSPrivateKeyFilePath))
				require.NoError(t, os.Link(
					config.A9.TLSCertificateFilePath,
					config.A9.TLSPrivateKeyFilePath,
				))
			},
		},
		{
			name: "writable parent",
			mutate: func(t *testing.T, config *options.Options) {
				directory := filepath.Join(a9TestDirectory(t), "writable")
				require.NoError(t, os.Mkdir(directory, 0o700))
				require.NoError(t, os.Chmod(directory, 0o770))
				path := filepath.Join(directory, "private-key")
				require.NoError(t, os.WriteFile(
					path,
					[]byte("private-key"),
					0o600,
				))
				config.A9.TLSPrivateKeyFilePath = path
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := validA9RuntimeOptions(t)
			config.PreflightA9RuntimeFiles = true
			config.A9.TopicCommitmentKeysFilePath =
				writeRestrictedA9Fixture(t, "topic")
			config.A9.TLSCertificateFilePath =
				writeRestrictedA9Fixture(t, "certificate")
			config.A9.TLSPrivateKeyFilePath =
				writeRestrictedA9Fixture(t, "private-key")
			testCase.mutate(t, &config)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			require.False(t, runA9MaterialMode(
				config,
				strings.NewReader("unused"),
				&stdout,
				&stderr,
			))
			require.Empty(t, stdout.String())
			require.Equal(t, a9MaterialFailureOutput, stderr.String())
		})
	}
}

func TestA9FileMetadataContractsRejectEverySpecialModeBit(t *testing.T) {
	path := writeRestrictedA9Fixture(t, "special-mode-metadata")
	base, err := os.Lstat(path)
	require.NoError(t, err)
	for _, special := range []os.FileMode{
		os.ModeSetuid,
		os.ModeSetgid,
		os.ModeSticky,
	} {
		info := a9ModeOverrideFileInfo{
			FileInfo: base,
			mode:     base.Mode() | special,
		}
		require.False(t, provisionedA9FileInfoValid(info, a9MaterialMaxBytes))
		for _, kind := range []a9RuntimeFileKind{
			a9RuntimeTopicKeys,
			a9RuntimeTLSCertificate,
			a9RuntimeTLSPrivateKey,
		} {
			require.False(t, a9RuntimeFileInfoValid(
				info,
				kind,
				a9MaterialMaxBytes,
			))
		}
	}
}

func TestA9FilePreflightRejectsFinalEntrySwap(t *testing.T) {
	config := validA9RuntimeOptions(t)
	config.PreflightA9RuntimeFiles = true
	config.A9.TopicCommitmentKeysFilePath = writeRestrictedA9Fixture(t, "topic")
	config.A9.TLSCertificateFilePath = writeRestrictedA9Fixture(t, "certificate")
	config.A9.TLSPrivateKeyFilePath = writeRestrictedA9Fixture(t, "private-key")
	topicPath := config.A9.TopicCommitmentKeysFilePath
	movedPath := topicPath + "-opened"
	swapped := false
	a9MaterialTestHook = func(stage string) {
		if stage != a9MaterialHookPreflightFileOpened || swapped {
			return
		}
		swapped = true
		require.NoError(t, os.Rename(topicPath, movedPath))
		require.NoError(t, os.WriteFile(topicPath, []byte("replacement"), 0o600))
	}
	t.Cleanup(func() { a9MaterialTestHook = nil })

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	require.False(t, runA9MaterialMode(
		config,
		strings.NewReader("unused"),
		&stdout,
		&stderr,
	))
	require.Empty(t, stdout.String())
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
	replacement, err := os.ReadFile(topicPath)
	require.NoError(t, err)
	require.Equal(t, []byte("replacement"), replacement)
	original, err := os.ReadFile(movedPath)
	require.NoError(t, err)
	require.Equal(t, []byte("topic"), original)
}

func TestA9FilePreflightRejectsParentReplacement(t *testing.T) {
	directory := a9TestDirectory(t)
	parent := filepath.Join(directory, "parent")
	movedParent := filepath.Join(directory, "moved-parent")
	require.NoError(t, os.Mkdir(parent, 0o700))
	topicPath := filepath.Join(parent, "topic")
	require.NoError(t, os.WriteFile(topicPath, []byte("topic"), 0o600))
	config := validA9RuntimeOptions(t)
	config.PreflightA9RuntimeFiles = true
	config.A9.TopicCommitmentKeysFilePath = topicPath
	config.A9.TLSCertificateFilePath = writeRestrictedA9Fixture(t, "certificate")
	config.A9.TLSPrivateKeyFilePath = writeRestrictedA9Fixture(t, "private-key")
	swapped := false
	a9MaterialTestHook = func(stage string) {
		if stage != a9MaterialHookPreflightFileOpened || swapped {
			return
		}
		swapped = true
		require.NoError(t, os.Rename(parent, movedParent))
		require.NoError(t, os.Mkdir(parent, 0o700))
		require.NoError(t, os.WriteFile(topicPath, []byte("replacement"), 0o600))
	}
	t.Cleanup(func() { a9MaterialTestHook = nil })

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	require.False(t, runA9MaterialMode(
		config,
		strings.NewReader("unused"),
		&stdout,
		&stderr,
	))
	require.Empty(t, stdout.String())
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
}

func TestRailwayProvisioningRequiresFixedVolumePaths(t *testing.T) {
	t.Setenv("RAILWAY_PROJECT_ID", "fixture-project")
	config := options.Options{ProvisionA9Material: a9TLSCertificateMaterial}
	config.A9.TLSCertificateFilePath = filepath.Join(
		a9RailwayMaterialDirectory,
		"sibling.pem",
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	require.False(t, runA9MaterialMode(
		config,
		strings.NewReader("material"),
		&stdout,
		&stderr,
	))
	require.Empty(t, stdout.String())
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
}

func TestA9MaterialModesAreCLIOnlyAndMutuallyExclusive(t *testing.T) {
	for _, args := range [][]string{
		{"--provision-a9-material=topic-commitment-keys"},
		{"--preflight-a9-runtime-files"},
	} {
		require.True(t, a9MaterialModeRequested(args))
	}
	require.False(t, a9MaterialModeRequested([]string{
		"--",
		"--preflight-a9-runtime-files",
	}))
	require.False(t, a9MaterialModeValid(options.Options{
		ProvisionA9Material:     a9TLSCertificateMaterial,
		PreflightA9RuntimeFiles: true,
	}))
	require.False(t, a9MaterialModeValid(options.Options{
		ProvisionA9Material:       a9TLSCertificateMaterial,
		PreflightLegacyRetirement: true,
	}))
}

func TestA9MaterialPanicBoundaryEmitsOnlyFixedFailure(t *testing.T) {
	var stderr bytes.Buffer
	completed := runWithA9MaterialPanicBoundary(
		func() { panic("fixture-secret-must-not-escape") },
		&stderr,
	)
	require.False(t, completed)
	require.Equal(t, a9MaterialFailureOutput, stderr.String())
}

func TestA9MaterialCLIIsFixedOutputAndExitsBeforeRuntime(t *testing.T) {
	if helperCase := os.Getenv("A9_MATERIAL_HELPER_CASE"); helperCase != "" {
		switch helperCase {
		case "success":
			os.Args = []string{
				"server",
				"--provision-a9-material=tls-private-key",
				"--api",
				"--xmtp-listener",
				"--listener-type=v4",
				"--hytch-secure-vault",
			}
		case "invalid-choice":
			os.Args = []string{
				"server",
				"--provision-a9-material=fixture-secret-must-not-escape",
			}
		case "help":
			os.Args = []string{
				"server",
				"--preflight-a9-runtime-files",
				"--help",
			}
		case "conflicting-mode":
			os.Args = []string{
				"server",
				"--preflight-a9-runtime-files",
				"--preflight-legacy-retirement",
			}
		case "completion-empty", "completion-value":
			os.Args = []string{
				"server",
				"--provision-a9-material=tls-private-key",
			}
		case "positional-before-double-dash":
			os.Args = []string{
				"server",
				"--provision-a9-material=tls-private-key",
				"fixture-secret-must-not-escape",
			}
		case "positional-after-double-dash":
			os.Args = []string{
				"server",
				"--provision-a9-material=tls-private-key",
				"--",
				"fixture-secret-must-not-escape",
			}
		case "preflight-positional-after-double-dash":
			os.Args = []string{
				"server",
				"--preflight-a9-runtime-files",
				"--",
				"fixture-secret-must-not-escape",
			}
		default:
			panic("unknown helper case")
		}
		runServer()
		if helperCase == "success" {
			os.Exit(0)
		}
		return
	}

	for _, helperCase := range []string{
		"success",
		"invalid-choice",
		"help",
		"conflicting-mode",
		"completion-empty",
		"completion-value",
		"positional-before-double-dash",
		"positional-after-double-dash",
		"preflight-positional-after-double-dash",
	} {
		t.Run(helperCase, func(t *testing.T) {
			path := filepath.Join(a9TestDirectory(t), "private-key")
			commandContext, cancel := context.WithTimeout(
				t.Context(),
				5*time.Second,
			)
			defer cancel()
			command := exec.CommandContext(
				commandContext,
				os.Args[0],
				"-test.run=^TestA9MaterialCLIIsFixedOutputAndExitsBeforeRuntime$",
			)
			command.Env = []string{
				"A9_MATERIAL_HELPER_CASE=" + helperCase,
				"BRIDGE_A9_TLS_PRIVATE_KEY_FILE_PATH=" + path,
				"GOTRACEBACK=none",
			}
			if helperCase == "completion-empty" {
				command.Env = append(command.Env, "GO_FLAGS_COMPLETION=")
			}
			if helperCase == "completion-value" {
				command.Env = append(command.Env, "GO_FLAGS_COMPLETION=1")
			}
			command.Stdin = strings.NewReader("fixture-material")
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			err := command.Run()
			require.NoError(t, commandContext.Err())

			if helperCase == "success" {
				require.NoError(t, err)
				require.Equal(
					t,
					a9ProvisionPassOutput+a9TLSPrivateKeyVariable+"\n",
					stdout.String(),
				)
				require.Empty(t, stderr.String())
				require.True(t, restrictedA9FileValid(path))
			} else {
				require.Error(t, err)
				require.Empty(t, stdout.String())
				require.Equal(t, a9MaterialFailureOutput, stderr.String())
				require.NoFileExists(t, path)
			}
			require.NotContains(t, stdout.String(), path)
			require.NotContains(t, stderr.String(), path)
			require.NotContains(t, stdout.String(), "fixture-material")
			require.NotContains(t, stderr.String(), "fixture-material")
			require.NotContains(
				t,
				stderr.String(),
				"fixture-secret-must-not-escape",
			)
		})
	}
}

func writeRestrictedA9Fixture(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(a9TestDirectory(t), "material")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func a9TestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	return directory
}
