package daemon

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// LogWatcher watches a log file for changes using fsnotify and emits new lines.
// It handles log rotation by detecting inode changes and reopening the file.
type LogWatcher struct {
	path     string
	file     *os.File
	watcher  *fsnotify.Watcher
	position int64
	inode    uint64
	output   chan string
	done     chan struct{}
	started  bool
	logger   observability.Logger
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewLogWatcher creates a new log watcher for the specified file path.
func NewLogWatcher(ctx context.Context, path string, logger observability.Logger) (*LogWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	watcherCtx, cancel := context.WithCancel(ctx)

	lw := &LogWatcher{
		path:    path,
		watcher: watcher,
		output:  make(chan string, 100),
		done:    make(chan struct{}),
		logger:  logger,
		ctx:     watcherCtx,
		cancel:  cancel,
	}

	return lw, nil
}

// Start begins watching the file for changes.
func (w *LogWatcher) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Open the log file
	if err := w.openFile(); err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Add file to fsnotify watcher
	if err := w.watcher.Add(w.path); err != nil {
		w.closeFile()
		return fmt.Errorf("failed to watch file: %w", err)
	}

	// Start the watch loop
	w.started = true
	go w.watchLoop()

	return nil
}

// Lines returns a channel that emits new log lines as they are written.
func (w *LogWatcher) Lines() <-chan string {
	return w.output
}

// Close stops the watcher and cleans up resources.
func (w *LogWatcher) Close() error {
	w.cancel()
	if w.started {
		<-w.done
	} else {
		// watchLoop never started; clean up directly
		w.watcher.Close()
		close(w.output)
		close(w.done)
	}
	return nil
}

// openFile opens the log file and stores its inode for rotation detection.
func (w *LogWatcher) openFile() error {
	file, err := os.Open(w.path)
	if err != nil {
		return err
	}

	// Get file info for inode
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return err
	}

	// Get inode from stat (Linux-specific)
	sysStat, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		file.Close()
		return fmt.Errorf("failed to get file stat")
	}

	w.file = file
	w.inode = sysStat.Ino

	// Seek to end of file to start tailing from current position
	position, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		w.closeFile()
		return err
	}
	w.position = position

	return nil
}

// closeFile closes the current file handle.
func (w *LogWatcher) closeFile() {
	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
}

// watchLoop is the main event loop that watches for file changes.
func (w *LogWatcher) watchLoop() {
	defer close(w.done)
	defer close(w.output)
	defer w.watcher.Close()
	defer w.closeFile()

	for {
		select {
		case <-w.ctx.Done():
			w.logger.Debug(w.ctx, "log watcher stopped", "path", w.path)
			return

		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}

			w.handleEvent(event)

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.logger.Error(w.ctx, "fsnotify error", "error", err, "path", w.path)
		}
	}
}

// handleEvent processes fsnotify events.
func (w *LogWatcher) handleEvent(event fsnotify.Event) {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch {
	case event.Op&fsnotify.Write == fsnotify.Write:
		// File was written to - read new lines
		w.readNewLines()

	case event.Op&fsnotify.Create == fsnotify.Create:
		// File was created (rotation happened)
		w.logger.Debug(w.ctx, "log file created (rotation detected)", "path", w.path)
		w.handleRotation()

	case event.Op&fsnotify.Remove == fsnotify.Remove:
		// File was removed (rotation in progress)
		w.logger.Debug(w.ctx, "log file removed (rotation in progress)", "path", w.path)

	case event.Op&fsnotify.Rename == fsnotify.Rename:
		// File was renamed (rotation happened)
		w.logger.Debug(w.ctx, "log file renamed (rotation detected)", "path", w.path)
		w.handleRotation()
	}
}

// readNewLines reads new lines from the current file position.
func (w *LogWatcher) readNewLines() {
	if w.file == nil {
		return
	}

	// Seek to last known position
	_, err := w.file.Seek(w.position, io.SeekStart)
	if err != nil {
		w.logger.Error(w.ctx, "failed to seek in log file", "error", err, "path", w.path)
		return
	}

	// Read new lines
	scanner := bufio.NewScanner(w.file)
	for scanner.Scan() {
		line := scanner.Text()
		select {
		case w.output <- line:
			// Successfully sent line
		case <-w.ctx.Done():
			return
		default:
			// Channel is full, skip line to avoid blocking
			w.logger.Warn(w.ctx, "log watcher output channel full, dropping line", "path", w.path)
		}
	}

	if err := scanner.Err(); err != nil {
		w.logger.Error(w.ctx, "error reading log file", "error", err, "path", w.path)
	}

	// Update position
	position, err := w.file.Seek(0, io.SeekCurrent)
	if err == nil {
		w.position = position
	}
}

// handleRotation detects and handles log file rotation.
func (w *LogWatcher) handleRotation() {
	// Check if file still exists at the same path
	stat, err := os.Stat(w.path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, will be created soon
			w.logger.Debug(w.ctx, "waiting for rotated file to be created", "path", w.path)
			return
		}
		w.logger.Error(w.ctx, "failed to stat log file", "error", err, "path", w.path)
		return
	}

	// Get new inode
	sysStat, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		w.logger.Error(w.ctx, "failed to get file stat during rotation", "path", w.path)
		return
	}

	newInode := sysStat.Ino

	// Check if inode changed (rotation occurred)
	if newInode != w.inode {
		w.logger.Info(w.ctx, "log rotation detected, reopening file",
			"path", w.path,
			"old_inode", w.inode,
			"new_inode", newInode)

		// Close old file
		w.closeFile()

		// Open new file
		if err := w.openFile(); err != nil {
			w.logger.Error(w.ctx, "failed to reopen log file after rotation", "error", err, "path", w.path)
			return
		}

		// Read any initial content from the new file
		w.readNewLines()
	}
}

// SeekToEnd seeks to the end of the log file, skipping historical content.
func (w *LogWatcher) SeekToEnd() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return fmt.Errorf("file not open")
	}

	position, err := w.file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("failed to seek to end: %w", err)
	}

	w.position = position
	return nil
}

// ReadHistoricalLines reads the last n lines from the log file before starting to tail.
// This should be called after Start() but before consuming from Lines().
func (w *LogWatcher) ReadHistoricalLines(n int) ([]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil, fmt.Errorf("file not open")
	}

	// Get file size
	stat, err := w.file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	fileSize := stat.Size()
	if fileSize == 0 {
		return []string{}, nil
	}

	// For simplicity, read entire file and return last n lines
	// This is acceptable for log files which are typically rotated before becoming huge
	_, err = w.file.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("failed to seek to start: %w", err)
	}

	var lines []string
	scanner := bufio.NewScanner(w.file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Return last n lines
	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	// Seek to end for tailing
	position, err := w.file.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("failed to seek to end: %w", err)
	}
	w.position = position

	return lines, nil
}
