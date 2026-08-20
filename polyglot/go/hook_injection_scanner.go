package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// HookInjectionScanner detects hook injection artifacts in mobile runtimes.
type HookInjectionScanner struct {
	score    int
	finders   []Finder
	reporter  ReportWriter
}

// Score represents risk level (0-100).
const (
	ScoreSafe     = 25
	ScoreSlightlyCompromised = 50
	ScoreModerateRisk = 75
	ScoreHighRisk    = 90
)

// Verdict is the final posture assessment.
type Verdict struct {
	Score       int
	Level       string
	Finds       []Finding
	Timestamp   string
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.
type Finder interface {
	Name() string
	Scan() ([]Finding, error)
}

// ReportWriter abstracts output formatting.
type ReportWriter interface {
	Write(v Verdict) (int, int64, error)
}

var defaultFinders = []Finder{
	&MemoryPatternScanner{},
	&FilesystemHookScanner{},
	&ProcessIntegrityScanner{},
	&KnownLibrariesScanner{},
}

// Finding represents a single detection artifact.
type Finding struct {
	Category   string
	Source     string
	Pattern    string
	Offset     int64
	MatchedLen int
	Metadata   map[string]string
}

// Finder interface for pluggable detection modules.