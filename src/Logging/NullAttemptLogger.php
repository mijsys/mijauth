<?php
/**
 * MijAuth - Null Attempt Logger
 *
 * @package   MijAuth
 * @author    MijagiKutasamoto
 * @license   MIT
 */

declare(strict_types=1);

namespace MijAuth\Logging;

/**
 * No-op logger for authorization attempts
 */
class NullAttemptLogger implements AttemptLoggerInterface
{
    public function logAttempt(array $context): void
    {
        // Intentionally no-op
    }
}
