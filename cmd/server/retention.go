package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/database"
)

func pruneCommand(args []string, out io.Writer) error {
	f := flag.NewFlagSet("prune", flag.ContinueOnError)
	file := f.String("config", "/etc/argus-c2/server.json", "server configuration")
	days := f.Int("retain-days", database.DefaultRetentionDays, "retain task history for at least this many days after its deadlines")
	limit := f.Int("limit", 200, "maximum completed tasks per batch, 1-1000")
	apply := f.Bool("apply", false, "delete the eligible batch; default is preview only")
	backup := f.String("backup", "", "new verified snapshot file required with -apply")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *apply {
		if *backup == "" {
			return errors.New("-apply requires -backup in a private directory")
		}
		parent, err := os.Stat(filepath.Dir(*backup))
		if err != nil {
			return err
		}
		if !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
			return errors.New("backup directory must have mode 0700")
		}
	} else if *backup != "" {
		return errors.New("-backup is only used with -apply")
	}
	c, err := config.LoadServer(*file)
	if err != nil {
		return err
	}
	s, err := database.Open(c.StateDir, false)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var p database.PruneReport
	if *apply {
		p, err = s.Prune(ctx, *days, *limit, *backup)
	} else {
		p, err = s.PreviewPrune(ctx, *days, *limit)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(p)
}
