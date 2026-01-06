<?php

declare(strict_types=1);

namespace Mounir\RuntimeGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mounir\RuntimeGuard\Contracts\ResponseMode;
use Mounir\RuntimeGuard\Contracts\ThreatLevel;
use Mounir\RuntimeGuard\Exceptions\ThreatDetectedException;
use Mounir\RuntimeGuard\GuardManager;
use Mounir\RuntimeGuard\Support\InspectionContext;
use Symfony\Component\HttpFoundation\Response;

/**
 * HTTP middleware for automatic request inspection.
 */
class RuntimeGuardMiddleware
{
    public function __construct(
        protected GuardManager $manager,
    ) {}

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next, ?string $profile = null): Response
    {
        // Skip if globally disabled
        if (! $this->manager->isEnabled()) {
            return $next($request);
        }

        // Create inspection context
        $context = InspectionContext::fromRequest($request);

        // Check exclusions
        if ($this->manager->shouldExclude($context)) {
            return $next($request);
        }

        // Gather input to inspect
        $input = $this->gatherInput($request);

        // Run inspection
        $pipelineResult = $this->manager->inspectWithContext($input, $context, $profile);

        // Handle results based on mode
        if ($pipelineResult->hasFailed()) {
            $this->handleFailure($pipelineResult, $context, $request);
        }

        return $next($request);
    }

    /**
     * Gather input from request based on configuration.
     */
    protected function gatherInput(Request $request): array
    {
        $input = [];
        $config = $this->manager->getConfig();

        if ($config['request']['inspect_query'] ?? true) {
            $input['query'] = $request->query->all();
        }

        if ($config['request']['inspect_body'] ?? true) {
            $input['body'] = $request->post();
        }

        if ($config['request']['inspect_headers'] ?? false) {
            $input['headers'] = $this->filterHeaders($request->headers->all());
        }

        if ($config['request']['inspect_cookies'] ?? false) {
            $input['cookies'] = $request->cookies->all();
        }

        return $input;
    }

    /**
     * Filter sensitive headers.
     */
    protected function filterHeaders(array $headers): array
    {
        $exclude = ['cookie', 'authorization', 'x-csrf-token', 'x-xsrf-token'];

        return array_filter(
            $headers,
            fn (string $key) => ! in_array(strtolower($key), $exclude, true),
            ARRAY_FILTER_USE_KEY
        );
    }

    /**
     * Handle inspection failure.
     */
    protected function handleFailure(
        \Mounir\RuntimeGuard\Pipeline\PipelineResult $result,
        InspectionContext $context,
        Request $request
    ): void {
        $mode = $this->manager->getResponseMode();
        $highestLevel = $result->getHighestThreatLevel();

        // Report to reporters
        foreach ($result->getFailedResults() as $guardResult) {
            $this->manager->report($guardResult, $context);
        }

        // Check if we should block
        if ($this->shouldBlock($mode, $highestLevel)) {
            $failedResult = $result->getFailedResults()[0] ?? null;

            if ($failedResult) {
                throw ThreatDetectedException::fromResult($failedResult);
            }
        }
    }

    /**
     * Determine if request should be blocked.
     */
    protected function shouldBlock(ResponseMode $mode, ThreatLevel $level): bool
    {
        if ($mode === ResponseMode::DRY_RUN) {
            return false;
        }

        if ($mode !== ResponseMode::BLOCK) {
            return false;
        }

        $threshold = ThreatLevel::tryFrom(
            $this->manager->getConfig()['block_threshold'] ?? 'high'
        ) ?? ThreatLevel::HIGH;

        return $level->weight() >= $threshold->weight();
    }
}
