package leaf

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopasspw/gopass/internal/backend/crypto/plain"
	"github.com/gopasspw/gopass/internal/backend/storage/fs"
	"github.com/gopasspw/gopass/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGPG(t *testing.T) {
	ctx := config.NewContextInMemory()

	ctx, _, _ = captureOutput(t, ctx)

	s, err := createSubStore(t)
	require.NoError(t, err)

	require.NoError(t, s.ImportMissingPublicKeys(ctx))

	newRecp := "A3683834"
	err = s.AddRecipient(ctx, newRecp)
	require.NoError(t, err)

	require.NoError(t, s.ImportMissingPublicKeys(ctx))
}

type unsafeIDExporter struct{}

func (unsafeIDExporter) ExportPublicKey(_ context.Context, _ string) ([]byte, error) {
	return make([]byte, 64), nil
}

// TestPublicKeyHelpersRejectUnsafeIDs verifies that the read and write
// entry points for .public-keys/ files refuse recipient IDs that contain
// path separators or dot segments, so a malicious .gpg-id from a shared
// repository cannot make gopass read or write files outside the key
// directories.
func TestPublicKeyHelpersRejectUnsafeIDs(t *testing.T) {
	t.Parallel()

	ctx := config.NewContextInMemory()

	tempdir := t.TempDir()

	_, _, err := createStore(tempdir, nil, nil)
	require.NoError(t, err)

	ctx, _, _ = captureOutput(t, ctx)

	s := &Store{
		alias:   "",
		path:    tempdir,
		crypto:  plain.New(),
		storage: fs.New(tempdir),
	}

	unsafe := []string{"../evil", "foo/bar", `foo\bar`, "..", ""}
	for _, id := range unsafe {
		_, err := s.exportPublicKey(ctx, unsafeIDExporter{}, id)
		require.Error(t, err, "exportPublicKey must reject %q", id)

		_, err = s.getPublicKey(ctx, id)
		require.Error(t, err, "getPublicKey must reject %q", id)

		_, err = s.decodePublicKey(ctx, id)
		require.Error(t, err, "decodePublicKey must reject %q", id)
	}

	// No file outside .public-keys/ may have been created.
	_, err = os.Stat(filepath.Join(tempdir, "evil"))
	assert.True(t, os.IsNotExist(err), "no file outside the key directory must be created")

	// A legitimate ID still works.
	path, err := s.exportPublicKey(ctx, unsafeIDExporter{}, "0xDEADBEEF")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(".public-keys", "0xDEADBEEF"), path)
	assert.True(t, s.storage.Exists(ctx, path))
}
