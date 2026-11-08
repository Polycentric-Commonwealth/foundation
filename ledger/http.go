package ledger

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/polycentric-commonwealth/foundation/record"
)

// MaxEntriesPerRequest limits GET ledger/entries.
const MaxEntriesPerRequest = 256

// Handler returns an http.Handler serving the log's read endpoints. Mount it
// so that request paths arrive relative to "<base>ledger/", for example with
// http.StripPrefix("/pc/ledger/", log.Handler()).
func (l *Log) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /checkpoint", l.serveCheckpoint)
	mux.HandleFunc("GET /entries", l.serveEntries)
	mux.HandleFunc("GET /proof/inclusion", l.serveInclusion)
	mux.HandleFunc("GET /proof/consistency", l.serveConsistency)
	mux.HandleFunc("GET /evidence", l.serveEvidence)
	return ensureLeadingSlash(mux)
}

// ensureLeadingSlash lets the handler work whether or not the mounting
// prefix kept the slash.
func ensureLeadingSlash(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) == 0 || r.URL.Path[0] != '/' {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/" + r.URL.Path
			r = r2
		}
		h.ServeHTTP(w, r)
	})
}

func (l *Log) serveCheckpoint(w http.ResponseWriter, r *http.Request) {
	cp, cosigs, ok := l.Latest()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no checkpoint yet"})
		return
	}
	if cosigs == nil {
		cosigs = []*record.Envelope{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"checkpoint": cp, "cosignatures": cosigs})
}

func (l *Log) serveEntries(w http.ResponseWriter, r *http.Request) {
	start, ok1 := uintParam(r, "start")
	end, ok2 := uintParam(r, "end")
	size, err := l.Storage.Size()
	if !ok1 || !ok2 || start > end || end > size || err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "start and end must satisfy start <= end <= size"})
		return
	}
	if end-start > MaxEntriesPerRequest {
		end = start + MaxEntriesPerRequest
	}
	entries := make([]json.RawMessage, 0, end-start)
	for i := start; i < end; i++ {
		e, err := l.Storage.Entry(i)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read entry"})
			return
		}
		entries = append(entries, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (l *Log) serveInclusion(w http.ResponseWriter, r *http.Request) {
	index, ok1 := uintParam(r, "index")
	size, ok2 := uintParam(r, "size")
	if !ok1 || !ok2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "index and size are required"})
		return
	}
	proof, err := l.InclusionProof(index, size)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hashes": encodeHashes(proof)})
}

func (l *Log) serveConsistency(w http.ResponseWriter, r *http.Request) {
	first, ok1 := uintParam(r, "first")
	second, ok2 := uintParam(r, "second")
	if !ok1 || !ok2 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "first and second are required"})
		return
	}
	proof, err := l.ConsistencyProof(first, second)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hashes": encodeHashes(proof)})
}

func (l *Log) serveEvidence(w http.ResponseWriter, r *http.Request) {
	index, ok := uintParam(r, "index")
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "index is required"})
		return
	}
	ev, err := l.Evidence(index)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	if ev.Cosignatures == nil {
		ev.Cosignatures = []*record.Envelope{}
	}
	writeJSON(w, http.StatusOK, ev)
}

func uintParam(r *http.Request, name string) (uint64, bool) {
	v, err := strconv.ParseUint(r.URL.Query().Get(name), 10, 64)
	return v, err == nil
}
