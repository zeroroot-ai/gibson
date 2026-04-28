package daemon

import (
	"context"
	"fmt"
	"sync"

	"github.com/zero-day-ai/gibson/internal/daemon/api"
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
		d.logger.Debug(context.Background(), "initializing mission manager")

		// Ensure infrastructure is initialized
		if d.infrastructure == nil {
			missionManagerInstance.initErr = fmt.Errorf("infrastructure not initialized")
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

		// Create mission manager with eventBus for orchestration events.
		// The pool replaces the three legacy stores (missionStore, missionRunStore, findingStore).
		missionManagerInstance.mgr = newMissionManager(
			d.config,
			d.logger.Slog(),
			d.registryAdapter,
			d.pool,
			d.checkpointStore,
			llmReg,
			d.callback,
			harnessFactory,
			d.targetStore,
			runLinker,
			d.infrastructure,
			d.infrastructure.otelStack,
			NewOrchestratorEventBusAdapterWithRedis(d.eventBus, d.redisEventStream, d.registryTenant), // Bridge events to Redis Streams
			d.missionAuthzStore, // May be nil when authz is disabled — manager guards against that
		)

		d.logger.Info(context.Background(), "mission manager initialized")
	})

	if missionManagerInstance.initErr != nil {
		return missionManagerInstance.initErr
	}

	// Set the mission manager on the daemon instance
	d.missionManager = missionManagerInstance.mgr
	return nil
}

// RunMissionWithManager starts a mission by reference using the mission manager.
// This is the implementation for the DaemonInterface.RunMission method. Inline
// construction and YAML file paths were removed under spec mission-api-only-cleanup.
func (d *daemonImpl) RunMissionWithManager(ctx context.Context, missionDefinitionID string, targetID string, variables map[string]string, memoryContinuity string) (<-chan api.MissionEventData, error) {
	d.logger.Info(ctx, "RunMission called",
		"mission_definition_id", missionDefinitionID,
		"target_id", targetID,
		"memory_continuity", memoryContinuity,
	)

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error(ctx, "failed to initialize mission manager", "error", err)
		return nil, fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Delegate to mission manager
	eventChan, err := d.missionManager.Run(ctx, missionDefinitionID, targetID, variables, memoryContinuity)
	if err != nil {
		d.logger.Error(ctx, "failed to start mission",
			"error", err,
			"mission_definition_id", missionDefinitionID,
			"target_id", targetID,
		)
		return nil, err
	}

	d.logger.Info(ctx, "mission started successfully",
		"mission_definition_id", missionDefinitionID,
		"target_id", targetID,
	)
	return eventChan, nil
}

// StopMissionWithManager stops a running mission using the mission manager.
// This is the implementation for the DaemonInterface.StopMission method.
func (d *daemonImpl) StopMissionWithManager(ctx context.Context, missionID string, force bool) error {
	d.logger.Info(ctx, "StopMission called via manager", "mission_id", missionID, "force", force)

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error(ctx, "failed to initialize mission manager", "error", err)
		return fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Delegate to mission manager
	if err := d.missionManager.Stop(ctx, missionID, force); err != nil {
		d.logger.Error(ctx, "failed to stop mission", "error", err, "mission_id", missionID)
		return err
	}

	d.logger.Info(ctx, "mission stopped successfully", "mission_id", missionID)
	return nil
}

// ListMissionsWithManager lists missions using the mission manager.
// This is the implementation for the DaemonInterface.ListMissions method.
func (d *daemonImpl) ListMissionsWithManager(ctx context.Context, activeOnly bool, limit, offset int) ([]api.MissionData, int, error) {
	d.logger.Debug(ctx, "ListMissions called via manager", "active_only", activeOnly, "limit", limit, "offset", offset)

	// Initialize mission manager if not already done
	if err := d.ensureMissionManager(); err != nil {
		d.logger.Error(ctx, "failed to initialize mission manager", "error", err)
		return nil, 0, fmt.Errorf("failed to initialize mission manager: %w", err)
	}

	// Delegate to mission manager
	missions, total, err := d.missionManager.List(ctx, activeOnly, limit, offset)
	if err != nil {
		d.logger.Error(ctx, "failed to list missions", "error", err)
		return nil, 0, err
	}

	d.logger.Debug(ctx, "listed missions", "total", total, "returned", len(missions))
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
