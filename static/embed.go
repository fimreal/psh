package static

import "embed"

//go:embed index.html app.js xterm/*
var Files embed.FS
