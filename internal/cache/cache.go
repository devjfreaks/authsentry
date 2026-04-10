package cache

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Cache struct {
	db         *sql.DB
	ttlSeconds int64
}

func New(path string, ttlHours int) (*Cache, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=4000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite is single-writer

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &Cache{db: db, ttlSeconds: int64(ttlHours) * 3600}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ip_cache (
			ip        TEXT PRIMARY KEY,
			data      TEXT NOT NULL,
			cached_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_cached_at ON ip_cache(cached_at);
	`)
	return err
}

func (c *Cache) Get(ip string) (map[string]interface{}, error) {
	row := c.db.QueryRow(
		`SELECT data, cached_at FROM ip_cache WHERE ip = ?`, ip,
	)

	var data string
	var cachedAt int64
	if err := row.Scan(&data, &cachedAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	if time.Now().Unix()-cachedAt > c.ttlSeconds {
		return nil, nil // stale
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c *Cache) Set(ip string, data map[string]interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = c.db.Exec(
		`INSERT OR REPLACE INTO ip_cache (ip, data, cached_at) VALUES (?, ?, ?)`,
		ip, string(b), time.Now().Unix(),
	)
	return err
}

func (c *Cache) Stats() (count int, oldest time.Time, err error) {
	row := c.db.QueryRow(`SELECT COUNT(*), MIN(cached_at) FROM ip_cache`)
	var minTs sql.NullInt64
	if err = row.Scan(&count, &minTs); err != nil {
		return
	}
	if minTs.Valid {
		oldest = time.Unix(minTs.Int64, 0)
	}
	return
}

func (c *Cache) Purge() (int64, error) {
	cutoff := time.Now().Unix() - c.ttlSeconds
	res, err := c.db.Exec(`DELETE FROM ip_cache WHERE cached_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (c *Cache) Close() error {
	return c.db.Close()
}
