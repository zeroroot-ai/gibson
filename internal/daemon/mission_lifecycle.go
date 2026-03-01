package daemon

import (
	"context"
	"fmt"
	"sync"

	"github.com/zero-day-ai/gibson/internal/daemon/api"
	"github.com/zero-day-ai/gibson/internal/observability"
)

// missionManagerHolder holds the mission manager instance and ensures thread-safe initialization
type missionManagerHolder struct {
	mu      sync.Once
	mgr     *missionManager
	initErr error
}

// missionManagerInstance is the singleton holder for the mission manager
var missionManagerInstance missionManagerHolder

// ensureMissionManager initializes the mission manager if not already initialized.
// This method is thread-safe and will only initialize once.
func (d *daemonImpl) ensureMissionManager() error {
	if d.missionManager != nil {
		return nil
	}

	// Use sync.Once to ensure thread-safe initialization
	missionManagerInstance.mu.Do(func() {
		d.logger.Debug("initializing mission manager")

		// Ensure infrastructure is initialized
		if d.infrastructure == nil {
			missionManagerInstance.initErr = fmt.Errorf("infrastructure not initialized")
			return
		}

		// Get finding store from infrastructure
		findingStore := d.infrastructure.findingStore
		if findingStore == nil {
			missionManagerInstance.initErr = fmt.Errorf("finding store not initialized in infrastructure")
			return
		}

		// Get LLM registry from infrastructure
		llmReg := d.infrastructure.llmRegistry
		if llmReg == nil {
			missionManagerInstance.initErr = fmt.Errorf("LLM registry not initialized in infrastructure")
			return
		}

		// Get harness factory from infrastructure
		harnessFactory := d.infrastructure.harnessFactory
		if harnessFactory == nil {
			missionManagerInstance.initErr = fmt.Errorf("harness factory not initialized in infrastructure")
			return
		}

		// Create mission run linker
		runLinker := d.infrastructure.runLinker
		if runLinker == nil {
			missionManagerInstance.initErr = fmt.Errorf("run linker not initialized in infrastructure")
			return
		}

		// Create activity logger based on config
		var activityLogger observability.ActivityLogger
		if d.config.ActivityLogging.Enabled {
			cfg := observability.ActivityLoggerConfig{
				Level:            observability.ParseActivityLevel(d.config.ActivityLogging.Level),
				MaxContentLength: d.config.ActivityLogging.MaxContentLength,
				BufferSize:       d.config.ActivityLogging.BufferSize,
				// Output defaults to os.Stdout in NewActivityLogger if nil
			}
			logger, err := observability.NewActivityLogger(cfg)
			if err != nil {
				d.logger.Warn("failed to create activity logger, using noop", "error", err)
				activityLogger = observability.NewNoopActivityLogger()
			} else {
				activityLogger = logger
				d.logger.Info("activity stream logging enabled",
					"level", d.config.ActivityLogging.Level,
					"output", d.config.ActivityLogging.Output,
				)
			}
		} else {
			activityLogger = observability.NewNoopActivityLogger()
			d.logger.Debug("activity stream logging disabled")
		}

		// Create mission manager
		missionManagerInstance.mgr = newMissionManager(
			d.config,
			d.logger,
			d.registryAdapter,
			d.missionStore,
			d.missionRunStore,
			findingStore,
			llmReg,
			d.callback,
			harnessFactory,
			d.targetStore,
			runLinker,
			d.infrastructure,
			d.infrastructure.missionTracer,
			activityLogger,
		)

		d.logger.Info("mission manager initialized")
	})

	if missionManagerInstance.initErr != nil {
		return missionManagerInstance.initErr
	}

	// Set the mission manager on the daemon instance
	d.missionManager = missionManagerInstance.mgr
	return nil
}

// RunMissionWithManager starts a mission using the mission manager.
// This is the implementation for the DaemonInterface.RunMission method.
func (d *daemonImpl) RunMissionWithManager(ctx context.Context, workflowPath string, missionID string, variables map[string]string, memoryContinuity string) (<-chan api.MissionEventData, error) {
	d.logger.Info("RunMission called", "workflow_path", workflowPath, "mission_id", missionID, "memory_continuity", memoryContinuity)

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error("failed to initialize mission manager", "error", err)
		return nil, fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Delegate to mission manager
	eventChan, err := d.missionManager.Run(ctx, workflowPath, missionID, variables, memoryContinuity)
	if err != nil {
		d.logger.Error("failed to start mission", "error", err, "workflow_path", workflowPath)
		return nil, err
	}

	d.logger.Info("mission started successfully", "mission_id", missionID)
	return eventChan, nil
}

// StopMissionWithManager stops a running mission using the mission manager.
// This is the implementation for the DaemonInterface.StopMission method.
func (d *daemonImpl) StopMissionWithManager(ctx context.Context, missionID string, force bool) error {
	d.logger.Info("StopMission called via manager", "mission_id", missionID, "force", force)

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error("failed to initialize mission manager", "error", err)
		return fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Delegate to mission manager
	if err := d.missionManager.Stop(ctx, missionID, force); err != nil {
		d.logger.Error("failed to stop mission", "error", err, "mission_id", missionID)
		return err
	}

	d.logger.Info("mission stopped successfully", "mission_id", missionID)
	return nil
}

// ListMissionsWithManager lists missions using the mission manager.
// This is the implementation for the DaemonInterface.ListMissions method.
func (d *daemonImpl) ListMissionsWithManager(ctx context.Context, activeOnly bool, limit, offset int) ([]api.MissionData, int, error) {
	d.logger.Debug("ListMissions called via manager", "active_only", activeOnly, "limit", limit, "offset", offset)

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error("failed to initialize mission manager", "error", err)
		return nil, 0, fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Delegate to mission manager
	missions, total, err := d.missionManager.List(ctx, activeOnly, limit, offset)
	if err != nil {
		d.logger.Error("failed to list missions", "error", err)
		return nil, 0, err
	}

	d.logger.Debug("listed missions", "total", total, "returned", len(missions))
	return missions, total, nil
}

// GetActiveMissionCount returns the number of currently active missions.
func (d *daemonImpl) GetActiveMissionCount() int {
	if d.missionManager == nil {
		return 0
	}
	return d.missionManager.GetActiveMissionCount()
}

// GetTotalMissionCount returns the total number of missions (active + completed).
func (d *daemonImpl) GetTotalMissionCount() int {
	if d.missionManager == nil {
		return 0
	}
	return d.missionManager.GetTotalMissionCount()
}
