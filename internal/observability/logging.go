package observability

import (
	"log/slog"
	"os"
)

func Logger() *slog.Logger { return slog.New(slog.NewJSONHandler(os.Stdout, nil)) }
