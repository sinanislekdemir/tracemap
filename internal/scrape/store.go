package scrape

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"traceroute/internal/sqliteutil"
)

// Store persists scrape jobs, pages and assets in a dedicated SQLite database,
// with FTS5 indexes over the searchable columns, and writes asset bodies to an
// on-disk archive tree.
type Store struct {
	db   *sql.DB
	dir  string
	path string
}

// Job captures the context of a scrape run, stored with the job row.
type Job struct {
	Label        string
	Depth        int
	Mode         string
	Scope        string
	Keywords     []string
	KeywordMatch string
	OptionsJSON  string
}

// JobSummary is the listing form of a job.
type JobSummary struct {
	ID        int64  `json:"id"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"createdAt"`
	Status    string `json:"status"`
	Depth     int    `json:"depth"`
	Mode      string `json:"mode"`
	Scope     string `json:"scope"`
	Keywords  string `json:"keywords"`
	Pages     int    `json:"pages"`
	Assets    int    `json:"assets"`
	Leaks     int    `json:"leaks"`
	Bytes     int64  `json:"bytes"`
}

// LeakSummary is the listing form of an open directory listing.
type LeakSummary struct {
	ID      int64  `json:"id"`
	JobID   int64  `json:"jobId"`
	URL     string `json:"url"`
	Status  int    `json:"status"`
	Kind    string `json:"kind"`
	Title   string `json:"title"`
	Entries int    `json:"entries"`
	Size    int    `json:"size"`
}

// Query selects a full-text search across the archive. Field is one of "all",
// "title", "meta", "url", "text", "html" or "filename"; an empty Field means
// "all".
type Query struct {
	JobID int64  `json:"jobId"`
	Field string `json:"field"`
	Query string `json:"query"`
	Limit int    `json:"limit"`
}

// Hit is one search result.
type Hit struct {
	Kind    string  `json:"kind"` // "page" or "asset"
	ID      int64   `json:"id"`
	JobID   int64   `json:"jobId"`
	URL     string  `json:"url"`
	Title   string  `json:"title"`
	Snippet string  `json:"snippet"`
	Rank    float64 `json:"rank"`
}

// PageDetail is the full stored document, for the preview pane.
type PageDetail struct {
	ID            int64    `json:"id"`
	JobID         int64    `json:"jobId"`
	URL           string   `json:"url"`
	FinalURL      string   `json:"finalUrl"`
	Depth         int      `json:"depth"`
	Status        int      `json:"status"`
	Title         string   `json:"title"`
	Meta          string   `json:"meta"`
	Lang          string   `json:"lang"`
	Canonical     string   `json:"canonical"`
	Text          string   `json:"text"`
	HTML          string   `json:"html"`
	HTMLTruncated bool     `json:"htmlTruncated"`
	Size          int      `json:"size"`
	Keywords      []string `json:"keywords"`
}

// PageSummary is the listing form of a stored document.
type PageSummary struct {
	ID      int64    `json:"id"`
	JobID   int64    `json:"jobId"`
	URL     string   `json:"url"`
	Title   string   `json:"title"`
	Status  int      `json:"status"`
	Depth   int      `json:"depth"`
	Size    int      `json:"size"`
	Matched []string `json:"matched"`
}

// AssetSummary is the listing form of a stored asset.
type AssetSummary struct {
	ID       int64  `json:"id"`
	JobID    int64  `json:"jobId"`
	URL      string `json:"url"`
	Filename string `json:"filename"`
	Ext      string `json:"ext"`
	MIME     string `json:"mime"`
	Kind     string `json:"kind"`
	Status   int    `json:"status"`
	Size     int64  `json:"size"`
}

// jobDir is the archive-relative directory of a job's assets.
func jobDir(id int64) string { return "job-" + strconv.FormatInt(id, 10) }

// Open opens (creating if needed) the scrape database and prepares the archive
// directory. An empty dbPath disables scraping and returns (nil, nil).
func Open(dbPath, archiveDir string) (*Store, error) {
	db, err := sqliteutil.Open(dbPath, scrapeSchema...)
	if err != nil {
		return nil, err
	}
	if db == nil {
		return nil, nil
	}
	if archiveDir != "" {
		if err := os.MkdirAll(archiveDir, 0o755); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return &Store{db: db, dir: archiveDir, path: dbPath}, nil
}

var scrapeSchema = []string{
	`CREATE TABLE IF NOT EXISTS scrape_job (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		label         TEXT NOT NULL,
		created_at    INTEGER NOT NULL,
		finished_at   INTEGER NOT NULL DEFAULT 0,
		depth         INTEGER NOT NULL DEFAULT 0,
		mode          TEXT NOT NULL DEFAULT '',
		scope         TEXT NOT NULL DEFAULT '',
		keywords      TEXT NOT NULL DEFAULT '[]',
		keyword_match TEXT NOT NULL DEFAULT 'any',
		options_json  TEXT NOT NULL DEFAULT '{}',
		status        TEXT NOT NULL DEFAULT 'running',
		pages         INTEGER NOT NULL DEFAULT 0,
		assets        INTEGER NOT NULL DEFAULT 0,
		bytes         INTEGER NOT NULL DEFAULT 0,
		error         TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_scrape_job_created ON scrape_job(created_at DESC)`,
	`CREATE TABLE IF NOT EXISTS scrape_page (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		job_id          INTEGER NOT NULL,
		url             TEXT NOT NULL,
		final_url       TEXT NOT NULL DEFAULT '',
		depth           INTEGER NOT NULL DEFAULT 0,
		status          INTEGER NOT NULL DEFAULT 0,
		content_type    TEXT NOT NULL DEFAULT '',
		title           TEXT NOT NULL DEFAULT '',
		meta_description TEXT NOT NULL DEFAULT '',
		meta_keywords   TEXT NOT NULL DEFAULT '',
		meta_json       TEXT NOT NULL DEFAULT '[]',
		meta            TEXT NOT NULL DEFAULT '',
		lang            TEXT NOT NULL DEFAULT '',
		canonical       TEXT NOT NULL DEFAULT '',
		fetched_at      INTEGER NOT NULL DEFAULT 0,
		size            INTEGER NOT NULL DEFAULT 0,
		sha256          TEXT NOT NULL DEFAULT '',
		text            TEXT NOT NULL DEFAULT '',
		html            TEXT NOT NULL DEFAULT '',
		html_truncated  INTEGER NOT NULL DEFAULT 0,
		matched_keywords TEXT NOT NULL DEFAULT '[]'
	)`,
	`CREATE INDEX IF NOT EXISTS idx_scrape_page_job ON scrape_page(job_id)`,
	`CREATE INDEX IF NOT EXISTS idx_scrape_page_url ON scrape_page(url)`,
	`CREATE TABLE IF NOT EXISTS scrape_asset (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		job_id     INTEGER NOT NULL,
		url        TEXT NOT NULL,
		final_url  TEXT NOT NULL DEFAULT '',
		filename   TEXT NOT NULL DEFAULT '',
		ext        TEXT NOT NULL DEFAULT '',
		mime       TEXT NOT NULL DEFAULT '',
		kind       TEXT NOT NULL DEFAULT '',
		status     INTEGER NOT NULL DEFAULT 0,
		size       INTEGER NOT NULL DEFAULT 0,
		sha256     TEXT NOT NULL DEFAULT '',
		fetched_at INTEGER NOT NULL DEFAULT 0,
		file_path  TEXT NOT NULL DEFAULT '',
		ref_url    TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_scrape_asset_job ON scrape_asset(job_id)`,
	`CREATE INDEX IF NOT EXISTS idx_scrape_asset_kind ON scrape_asset(job_id, kind)`,
	`CREATE TABLE IF NOT EXISTS scrape_leak (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		job_id     INTEGER NOT NULL,
		url        TEXT NOT NULL,
		final_url  TEXT NOT NULL DEFAULT '',
		status     INTEGER NOT NULL DEFAULT 0,
		kind       TEXT NOT NULL DEFAULT 'autoindex',
		title      TEXT NOT NULL DEFAULT '',
		entries    INTEGER NOT NULL DEFAULT 0,
		size       INTEGER NOT NULL DEFAULT 0,
		fetched_at INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_scrape_leak_job ON scrape_leak(job_id)`,
	`CREATE VIRTUAL TABLE IF NOT EXISTS page_fts USING fts5(
		title, meta, url, text, html,
		content='scrape_page', content_rowid='id',
		tokenize='unicode61 remove_diacritics 2'
	)`,
	`CREATE VIRTUAL TABLE IF NOT EXISTS asset_fts USING fts5(
		url, filename,
		content='scrape_asset', content_rowid='id',
		tokenize='unicode61 remove_diacritics 2'
	)`,
	`CREATE TRIGGER IF NOT EXISTS scrape_page_ai AFTER INSERT ON scrape_page BEGIN
		INSERT INTO page_fts(rowid, title, meta, url, text, html)
		VALUES (new.id, new.title, new.meta, new.url, new.text, new.html);
	END`,
	`CREATE TRIGGER IF NOT EXISTS scrape_page_ad AFTER DELETE ON scrape_page BEGIN
		INSERT INTO page_fts(page_fts, rowid, title, meta, url, text, html)
		VALUES ('delete', old.id, old.title, old.meta, old.url, old.text, old.html);
	END`,
	`CREATE TRIGGER IF NOT EXISTS scrape_asset_ai AFTER INSERT ON scrape_asset BEGIN
		INSERT INTO asset_fts(rowid, url, filename)
		VALUES (new.id, new.url, new.filename);
	END`,
	`CREATE TRIGGER IF NOT EXISTS scrape_asset_ad AFTER DELETE ON scrape_asset BEGIN
		INSERT INTO asset_fts(asset_fts, rowid, url, filename)
		VALUES ('delete', old.id, old.url, old.filename);
	END`,
}

// Path returns the database file path, or "" when scraping is disabled.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// BeginJob inserts a new job row and returns its id.
func (s *Store) BeginJob(ctx context.Context, job Job) (int64, error) {
	if s == nil {
		return 0, errors.New("scraping is disabled")
	}
	keywords, err := json.Marshal(job.Keywords)
	if err != nil {
		keywords = []byte("[]")
	}
	if job.KeywordMatch == "" {
		job.KeywordMatch = string(MatchAny)
	}
	if job.OptionsJSON == "" {
		job.OptionsJSON = "{}"
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO scrape_job (label, created_at, depth, mode, scope, keywords, keyword_match, options_json, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running')`,
		job.Label, time.Now().UnixMilli(), job.Depth, string(job.Mode), string(job.Scope),
		string(keywords), job.KeywordMatch, job.OptionsJSON)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishJob stamps a job's terminal status and error.
func (s *Store) FinishJob(ctx context.Context, id int64, status, errMsg string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE scrape_job SET status = ?, finished_at = ?, error = ? WHERE id = ?`,
		status, time.Now().UnixMilli(), errMsg, id)
	return err
}

// SavePage stores a document. The FTS index is updated by a trigger.
func (s *Store) SavePage(ctx context.Context, jobID int64, p Page) (int64, error) {
	if s == nil {
		return 0, errors.New("scraping is disabled")
	}
	truncated := 0
	if p.HTMLTruncated {
		truncated = 1
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO scrape_page (
			job_id, url, final_url, depth, status, content_type, title,
			meta_description, meta_keywords, meta_json, meta, lang, canonical,
			fetched_at, size, sha256, text, html, html_truncated, matched_keywords)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		jobID, p.URL, p.FinalURL, p.Depth, p.Status, p.ContentType, p.Title,
		p.MetaDescription, p.MetaKeywords, p.MetaJSON, p.MetaText, p.Lang, p.Canonical,
		time.Now().UnixMilli(), p.Size, p.SHA256, p.Text, p.HTML, truncated,
		encodeKeywords(p.MatchedKeywords))
	if err != nil {
		return 0, err
	}
	s.bumpJob(ctx, jobID, 1, 0, int64(p.Size))
	return res.LastInsertId()
}

// SaveAsset writes an asset's body to the archive and stores its metadata.
func (s *Store) SaveAsset(ctx context.Context, jobID int64, a Asset) (int64, error) {
	if s == nil {
		return 0, errors.New("scraping is disabled")
	}
	relPath := s.writeAsset(jobID, a)
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO scrape_asset (
			job_id, url, final_url, filename, ext, mime, kind, status,
			size, sha256, fetched_at, file_path, ref_url)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		jobID, a.URL, a.FinalURL, a.Filename, a.Ext, a.MIME, a.Kind, a.Status,
		a.Size, a.SHA256, time.Now().UnixMilli(), relPath, a.PageURL)
	if err != nil {
		return 0, err
	}
	s.bumpJob(ctx, jobID, 0, 1, a.Size)
	return res.LastInsertId()
}

// SaveLeak stores an open directory listing found by the index test.
func (s *Store) SaveLeak(ctx context.Context, jobID int64, l Leak) (int64, error) {
	if s == nil {
		return 0, errors.New("scraping is disabled")
	}
	if l.Kind == "" {
		l.Kind = "autoindex"
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO scrape_leak (job_id, url, final_url, status, kind, title, entries, size, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		jobID, l.URL, l.FinalURL, l.Status, l.Kind, l.Title, l.Entries, l.Size, time.Now().UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListLeaks returns a job's open directory listings.
func (s *Store) ListLeaks(ctx context.Context, jobID int64, limit int) ([]LeakSummary, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 5000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, job_id, url, status, kind, title, entries, size
		FROM scrape_leak WHERE job_id = ? ORDER BY id ASC LIMIT ?`, jobID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]LeakSummary, 0, 8)
	for rows.Next() {
		var l LeakSummary
		if err := rows.Scan(&l.ID, &l.JobID, &l.URL, &l.Status, &l.Kind, &l.Title, &l.Entries, &l.Size); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// writeAsset writes the body under the job's archive directory, content-
// addressed by SHA-256 so duplicate assets are stored once. It returns the
// archive-relative path, or "" when there is no body or no archive directory.
func (s *Store) writeAsset(jobID int64, a Asset) string {
	if s.dir == "" || len(a.Data) == 0 || a.SHA256 == "" {
		return ""
	}
	ext := a.Ext
	if ext == "" {
		ext = assetExtName(a.URL, a.MIME)
	}
	rel := filepath.Join(jobDir(jobID), "assets", a.SHA256[:2], a.SHA256+ext)
	abs := filepath.Join(s.dir, rel)
	if _, err := os.Stat(abs); err == nil {
		return rel
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return ""
	}
	if err := os.WriteFile(abs, a.Data, 0o644); err != nil {
		return ""
	}
	return rel
}

func (s *Store) bumpJob(ctx context.Context, jobID int64, pages, assets int, bytes int64) {
	_, _ = s.db.ExecContext(ctx, `
		UPDATE scrape_job SET pages = pages + ?, assets = assets + ?, bytes = bytes + ?
		WHERE id = ?`, pages, assets, bytes, jobID)
}

// ListJobs returns every job summary, newest first.
func (s *Store) ListJobs(ctx context.Context) ([]JobSummary, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT j.id, j.label, j.created_at, j.status, j.depth, j.mode, j.scope,
		       j.keywords, j.pages, j.assets, j.bytes,
		       (SELECT COUNT(*) FROM scrape_leak l WHERE l.job_id = j.id)
		FROM scrape_job j ORDER BY j.created_at DESC, j.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]JobSummary, 0, 16)
	for rows.Next() {
		var j JobSummary
		if err := rows.Scan(&j.ID, &j.Label, &j.CreatedAt, &j.Status, &j.Depth,
			&j.Mode, &j.Scope, &j.Keywords, &j.Pages, &j.Assets, &j.Bytes, &j.Leaks); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ListPages returns a job's stored documents, shallowest first.
func (s *Store) ListPages(ctx context.Context, jobID int64, limit int) ([]PageSummary, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 5000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, job_id, url, title, status, depth, size, matched_keywords
		FROM scrape_page WHERE job_id = ?
		ORDER BY depth ASC, id ASC LIMIT ?`, jobID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]PageSummary, 0, 32)
	for rows.Next() {
		var (
			p        PageSummary
			keywords string
		)
		if err := rows.Scan(&p.ID, &p.JobID, &p.URL, &p.Title, &p.Status, &p.Depth, &p.Size, &keywords); err != nil {
			return nil, err
		}
		p.Matched = decodeKeywords(keywords)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListAssets returns a job's stored assets, optionally filtered by kind.
func (s *Store) ListAssets(ctx context.Context, jobID int64, kind string, limit int) ([]AssetSummary, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 5000
	}
	sqlText := `
		SELECT id, job_id, url, filename, ext, mime, kind, status, size
		FROM scrape_asset WHERE job_id = ?`
	args := []any{jobID}
	if kind != "" {
		sqlText += " AND kind = ?"
		args = append(args, kind)
	}
	sqlText += " ORDER BY kind ASC, filename ASC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AssetSummary, 0, 32)
	for rows.Next() {
		var a AssetSummary
		if err := rows.Scan(&a.ID, &a.JobID, &a.URL, &a.Filename, &a.Ext, &a.MIME, &a.Kind, &a.Status, &a.Size); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Search runs a field-scoped full-text query. Field "all" searches pages and
// assets together and merges the ranked results.
func (s *Store) Search(ctx context.Context, q Query) ([]Hit, error) {
	if s == nil {
		return nil, errors.New("scraping is disabled")
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	field := strings.ToLower(strings.TrimSpace(q.Field))
	if field == "" {
		field = "all"
	}

	switch field {
	case "filename":
		return s.searchAssets(ctx, q, ftsMatch("filename", q.Query), limit)
	case "all":
		pages, err := s.searchPages(ctx, q, ftsMatch("", q.Query), limit)
		if err != nil {
			return nil, err
		}
		assets, err := s.searchAssets(ctx, q, ftsMatch("", q.Query), limit)
		if err != nil {
			return nil, err
		}
		return mergeHits(pages, assets, limit), nil
	case "title", "meta", "url", "text", "html":
		return s.searchPages(ctx, q, ftsMatch(field, q.Query), limit)
	default:
		return nil, fmt.Errorf("unknown search field %q", q.Field)
	}
}

func (s *Store) searchPages(ctx context.Context, q Query, expr string, limit int) ([]Hit, error) {
	sqlText := `
		SELECT p.id, p.job_id, p.url, p.title,
		       snippet(page_fts, -1, '[', ']', '…', 12), bm25(page_fts)
		FROM page_fts JOIN scrape_page p ON p.id = page_fts.rowid
		WHERE page_fts MATCH ?`
	args := []any{expr}
	if q.JobID > 0 {
		sqlText += " AND p.job_id = ?"
		args = append(args, q.JobID)
	}
	sqlText += " ORDER BY bm25(page_fts) LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Hit, 0, 16)
	for rows.Next() {
		var h Hit
		h.Kind = "page"
		if err := rows.Scan(&h.ID, &h.JobID, &h.URL, &h.Title, &h.Snippet, &h.Rank); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) searchAssets(ctx context.Context, q Query, expr string, limit int) ([]Hit, error) {
	sqlText := `
		SELECT a.id, a.job_id, a.url, a.filename,
		       snippet(asset_fts, -1, '[', ']', '…', 12), bm25(asset_fts)
		FROM asset_fts JOIN scrape_asset a ON a.id = asset_fts.rowid
		WHERE asset_fts MATCH ?`
	args := []any{expr}
	if q.JobID > 0 {
		sqlText += " AND a.job_id = ?"
		args = append(args, q.JobID)
	}
	sqlText += " ORDER BY bm25(asset_fts) LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Hit, 0, 16)
	for rows.Next() {
		var h Hit
		h.Kind = "asset"
		if err := rows.Scan(&h.ID, &h.JobID, &h.URL, &h.Title, &h.Snippet, &h.Rank); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// LoadPage returns a stored document for preview.
func (s *Store) LoadPage(ctx context.Context, id int64) (PageDetail, error) {
	if s == nil {
		return PageDetail{}, errors.New("scraping is disabled")
	}
	var (
		d         PageDetail
		truncated int
		keywords  string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, job_id, url, final_url, depth, status, title, meta, lang,
		       canonical, text, html, html_truncated, size, matched_keywords
		FROM scrape_page WHERE id = ?`, id).
		Scan(&d.ID, &d.JobID, &d.URL, &d.FinalURL, &d.Depth, &d.Status, &d.Title,
			&d.Meta, &d.Lang, &d.Canonical, &d.Text, &d.HTML, &truncated, &d.Size, &keywords)
	if err != nil {
		return PageDetail{}, err
	}
	d.HTMLTruncated = truncated != 0
	d.Keywords = decodeKeywords(keywords)
	return d, nil
}

// AssetPath returns the absolute on-disk path of a stored asset, or "" when it
// has no body (for example a redirect-only resource).
func (s *Store) AssetPath(ctx context.Context, id int64) (string, error) {
	if s == nil {
		return "", errors.New("scraping is disabled")
	}
	var rel, kind, mime string
	if err := s.db.QueryRowContext(ctx,
		`SELECT file_path, kind, mime FROM scrape_asset WHERE id = ?`, id).
		Scan(&rel, &kind, &mime); err != nil {
		return "", err
	}
	if rel == "" || s.dir == "" {
		return "", nil
	}
	return filepath.Join(s.dir, rel), nil
}

// DeleteJob removes a job, its pages and assets, and its archive directory.
func (s *Store) DeleteJob(ctx context.Context, id int64) error {
	if s == nil {
		return errors.New("scraping is disabled")
	}
	// Explicit deletes (rather than FK cascade) guarantee the FTS delete
	// triggers fire so the indexes stay consistent.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM scrape_page WHERE job_id = ?`, id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM scrape_asset WHERE job_id = ?`, id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM scrape_leak WHERE job_id = ?`, id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM scrape_job WHERE id = ?`, id); err != nil {
		return err
	}
	if s.dir != "" {
		_ = os.RemoveAll(filepath.Join(s.dir, jobDir(id)))
	}
	return nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	return s.db.Close()
}

// ftsMatch turns free-form user text into an FTS5 MATCH expression: each
// whitespace-separated term becomes a quoted phrase, optionally constrained to
// one column, and the terms are AND-ed. Column names are fixed by the caller.
func ftsMatch(field, query string) string {
	terms := strings.Fields(query)
	parts := make([]string, 0, len(terms))
	for _, term := range terms {
		quoted := `"` + strings.ReplaceAll(term, `"`, `""`) + `"`
		if field != "" {
			parts = append(parts, field+":"+quoted)
		} else {
			parts = append(parts, quoted)
		}
	}
	return strings.Join(parts, " AND ")
}

// mergeHits combines two ranked hit lists (ascending bm25 rank) into one,
// preserving order and capping at limit.
func mergeHits(a, b []Hit, limit int) []Hit {
	merged := make([]Hit, 0, len(a)+len(b))
	i, j := 0, 0
	for len(merged) < limit && (i < len(a) || j < len(b)) {
		switch {
		case i >= len(a):
			merged = append(merged, b[j])
			j++
		case j >= len(b):
			merged = append(merged, a[i])
			i++
		case a[i].Rank <= b[j].Rank:
			merged = append(merged, a[i])
			i++
		default:
			merged = append(merged, b[j])
			j++
		}
	}
	return merged
}

func encodeKeywords(words []string) string {
	if len(words) == 0 {
		return "[]"
	}
	b, err := json.Marshal(words)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func decodeKeywords(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
