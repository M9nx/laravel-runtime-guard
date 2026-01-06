<?php

declare(strict_types=1);

namespace M9nx\RuntimeGuard\Traits;

use Illuminate\Http\Request;
use M9nx\RuntimeGuard\Contracts\GuardManagerInterface;
use M9nx\RuntimeGuard\Contracts\ResponseMode;
use M9nx\RuntimeGuard\Exceptions\ThreatDetectedException;
use M9nx\RuntimeGuard\Pipeline\PipelineResult;
use M9nx\RuntimeGuard\Support\InspectionContext;

/**
 * Trait for easy guard inspection in controllers.
 */
trait InspectsInput
{
    /**
     * Inspect input and optionally throw on threat.
     *
     * @throws ThreatDetectedException
     */
    protected function inspectInput(mixed $input, array $context = []): PipelineResult
    {
        $manager = $this->getGuardManager();
        $inspectionContext = InspectionContext::forInput($input, $context);

        $result = $manager->inspectWithContext($input, $inspectionContext);

        if ($result->hasThreat() && $manager->getResponseMode() === ResponseMode::BLOCK) {
            $firstThreat = $result->getFirstThreat();

            throw ThreatDetectedException::fromResult($firstThreat);
        }

        return $result;
    }

    /**
     * Inspect request input.
     *
     * @throws ThreatDetectedException
     */
    protected function inspectRequest(?Request $request = null): PipelineResult
    {
        $request = $request ?? request();
        $manager = $this->getGuardManager();

        $input = $this->extractRequestInput($request);
        $context = InspectionContext::forRequest($request);

        $result = $manager->inspectWithContext($input, $context);

        if ($result->hasThreat() && $manager->getResponseMode() === ResponseMode::BLOCK) {
            $firstThreat = $result->getFirstThreat();

            throw ThreatDetectedException::fromResult($firstThreat);
        }

        return $result;
    }

    /**
     * Inspect specific request fields.
     *
     * @param  array<string>  $fields
     *
     * @throws ThreatDetectedException
     */
    protected function inspectRequestFields(array $fields, ?Request $request = null): PipelineResult
    {
        $request = $request ?? request();

        $input = $request->only($fields);

        return $this->inspectInput($input, [
            'source' => 'request',
            'fields' => $fields,
        ]);
    }

    /**
     * Inspect with a specific guard only.
     */
    protected function inspectWith(string $guardName, mixed $input, array $context = [])
    {
        return $this->getGuardManager()->inspectWith($guardName, $input, $context);
    }

    /**
     * Quick check if input contains threats (non-throwing).
     */
    protected function hasThreat(mixed $input, array $context = []): bool
    {
        $manager = $this->getGuardManager();
        $inspectionContext = InspectionContext::forInput($input, $context);

        return $manager->inspectWithContext($input, $inspectionContext)->hasThreat();
    }

    /**
     * Extract input from request for inspection.
     *
     * @return array<string, mixed>
     */
    protected function extractRequestInput(Request $request): array
    {
        $config = config('runtime-guard.middleware', []);
        $input = [];

        if ($config['inspect_query'] ?? true) {
            $input['query'] = $request->query->all();
        }

        if ($config['inspect_body'] ?? true) {
            $input['body'] = $request->post();
        }

        if ($config['inspect_headers'] ?? false) {
            $input['headers'] = $request->headers->all();
        }

        if ($config['inspect_cookies'] ?? false) {
            $input['cookies'] = $request->cookies->all();
        }

        return $input;
    }

    /**
     * Get the guard manager instance.
     */
    protected function getGuardManager(): GuardManagerInterface
    {
        return app(GuardManagerInterface::class);
    }
}
