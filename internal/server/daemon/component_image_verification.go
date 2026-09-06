// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	"github.com/zeroroot-ai/gibson/internal/platform/supplychain"
)

// verifyCatalogImages checks the release signature of every first-party image
// the catalog names, and reports which components may be offered (ADR-0015
// runtime verification, gibson#1639).
//
// Digest pinning already guarantees everyone runs the same bytes. It says
// nothing about whether we built those bytes — anyone who can push to the
// registry can produce a digest-shaped reference. This is the check that makes
// the pin mean something.
//
// Fail-closed, per component: a component whose image cannot be shown to come
// from the release pipeline is left out of the returned set, so no
// platform_enabled tuple is written for it and the platform does not offer it.
// One bad entry does not de-list the rest — the others verified, and taking the
// whole catalog down would make operators disable the check to get a platform
// back.
//
// A component naming no image (a connector fronting a remote MCP endpoint) and
// a third-party vendor image are both outside this seam and pass through: the
// release pipeline never signed them, and pretending otherwise would either
// block them forever or teach the check to accept unsigned images.
func verifyCatalogImages(
	ctx context.Context,
	verifier supplychain.Verifier,
	refs []componentcatalog.Ref,
	logger *slog.Logger,
) ([]componentcatalog.Ref, error) {
	if verifier == nil {
		return nil, errors.New("component image verification: no verifier wired; " +
			"refusing to seed unverified images as if they were verified")
	}

	// One image usually backs many components — every sandboxed tool shares the
	// executor. Verify each distinct image once: the result is a property of the
	// image, and seven round trips for one answer is just latency at startup.
	byImage := map[string][]componentcatalog.Ref{}
	for _, ir := range componentcatalog.ImageRefs() {
		byImage[ir.Image] = append(byImage[ir.Image], componentcatalog.Ref{Kind: ir.Kind, ID: ir.ID})
	}

	refused := map[string]error{} // component object → why
	for image, components := range byImage {
		if !supplychain.IsFirstParty(image) {
			logger.Debug("component image is not first-party; outside the release-signature seam",
				"image", image, "components", len(components))
			continue
		}
		if err := verifier.Verify(ctx, image); err != nil {
			for _, c := range components {
				refused[c.Kind+"/"+c.ID] = err
			}
			logger.Error("component image failed release-signature verification; not offering these components",
				"image", image,
				"components", len(components),
				"error", err)
		}
	}

	kept := make([]componentcatalog.Ref, 0, len(refs))
	for _, r := range refs {
		if _, bad := refused[r.Kind+"/"+r.ID]; !bad {
			kept = append(kept, r)
		}
	}
	if len(refused) == 0 {
		return kept, nil
	}

	names := make([]string, 0, len(refused))
	for n := range refused {
		names = append(names, n)
	}
	sort.Strings(names)
	return kept, fmt.Errorf(
		"component image verification: %d component(s) not offered because their image "+
			"could not be shown to come from the release pipeline: %s",
		len(names), strings.Join(names, ", "))
}

// defaultRegistryAuthDir is where the chart projects the registry pull
// credential for the daemon PROCESS. The pod's imagePullSecret authenticates
// the kubelet and nothing else, so the daemon needs its own copy to read an
// image's signature referrers off a private registry.
const defaultRegistryAuthDir = "/etc/gibson/registry-credential"

// registryAuthDir names the directory holding the docker config the
// verifier authenticates with. The environment variable exists so a test and a
// self-hosted layout can point somewhere else; there is no second code path.
func registryAuthDir() string {
	if dir := os.Getenv("GIBSON_REGISTRY_CREDENTIAL_DIR"); dir != "" {
		return dir
	}
	return defaultRegistryAuthDir
}

// componentImageVerifier builds the release-signature verifier the catalog seed
// uses. A plain function, not a method: the verifier holds no daemon state, and
// this is the one construction point.
func componentImageVerifier() supplychain.Verifier {
	return supplychain.NewSigstoreVerifier(registryAuthDir())
}
