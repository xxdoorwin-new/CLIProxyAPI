// Command fix_api_key_names is a one-off maintenance tool that repairs API
// key names left over by a historical bug (introduced in commit b713a7de,
// fixed in 043e05c0): binding a key without an explicit name used to store
// the raw configured-key value as its name instead of a friendly default.
// Affected rows have name == prefix, which a legitimately (manually) named
// key will never match, so this tool can identify and fix them precisely.
//
// It is safe to run against a live database and safe to re-run: once a row
// is renamed it no longer matches the name == prefix condition, so a second
// run is a no-op.
//
// Usage:
//
//	go run ./cmd/fix_api_key_names [flags]
//
// Flags:
//
//	--db       <path>  Path to the user-management sqlite database (default: "user-management.sqlite")
//	--dry-run          List the keys that would be renamed without changing anything (default: false)
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

type affectedKey struct {
	id       string
	username string
	oldName  string
	newName  string
}

func main() {
	dbPath := flag.String("db", "user-management.sqlite", "path to the user-management sqlite database")
	dryRun := flag.Bool("dry-run", false, "list the keys that would be renamed without changing anything")
	flag.Parse()

	ctx := context.Background()
	store, err := usermanagement.OpenSQLiteStore(ctx, usermanagement.SQLiteConfig{Path: *dbPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if errClose := store.Close(); errClose != nil {
			fmt.Fprintf(os.Stderr, "close database: %v\n", errClose)
		}
	}()

	db := store.DB()
	affected, err := listAffectedKeys(ctx, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query affected keys: %v\n", err)
		os.Exit(1)
	}
	if len(affected) == 0 {
		fmt.Println("no affected keys found; nothing to do")
		return
	}
	for _, key := range affected {
		fmt.Printf("key %s (user %s): %q -> %q\n", key.id, key.username, key.oldName, key.newName)
	}
	if *dryRun {
		fmt.Printf("dry run: %d key(s) would be renamed\n", len(affected))
		return
	}

	renamed, err := renameAffectedKeys(ctx, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rename affected keys: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("renamed %d key(s)\n", renamed)
}

func listAffectedKeys(ctx context.Context, db *sql.DB) ([]affectedKey, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT api_keys.id, users.username, api_keys.name
		FROM api_keys
		JOIN users ON users.id = api_keys.user_id
		WHERE api_keys.name = api_keys.prefix`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var affected []affectedKey
	for rows.Next() {
		var key affectedKey
		if err = rows.Scan(&key.id, &key.username, &key.oldName); err != nil {
			return nil, err
		}
		key.newName = key.username + "专用密钥"
		affected = append(affected, key)
	}
	return affected, rows.Err()
}

func renameAffectedKeys(ctx context.Context, db *sql.DB) (int64, error) {
	result, err := db.ExecContext(ctx, `
		UPDATE api_keys
		SET name = (SELECT username FROM users WHERE users.id = api_keys.user_id) || '专用密钥'
		WHERE name = prefix
			AND EXISTS (SELECT 1 FROM users WHERE users.id = api_keys.user_id)`)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
