/*
Copyright 2026 Zero Root AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// E8/gibson#805 cutover: the RegisterTenantWithPlatform provisioning step
// (which wrote the (tenant:<name>, parent, system_tenant:_system) registration
// tuple) was removed from ProvisionSteps. That concern now belongs to the
// declarative TenantGrants sub-CRD (#804), which writes the same tuple via
// grants.PlatformRegistrationTuple. This file's remaining test locks that the
// inline saga step is no longer wired into ProvisionSteps.

package flows

import (
	"testing"
)

// TestRegisterTenantWithPlatform_AbsentFromProvisionSteps asserts the step is
// no longer in the provision saga (E8/gibson#805): tenant→platform registration
// is now owned by the TenantGrants sub-CRD, not an inline saga step.
func TestRegisterTenantWithPlatform_AbsentFromProvisionSteps(t *testing.T) {
	t.Parallel()
	steps := ProvisionSteps(ProvisionDeps{FGA: &stubFGAClient{}, Vault: &stubVaultAdmin{}})
	for _, s := range steps {
		if s.Name() == "RegisterTenantWithPlatform" {
			t.Fatalf("RegisterTenantWithPlatform must NOT be in ProvisionSteps after E8/gibson#805; order: %s", namesOf(steps))
		}
	}
}
