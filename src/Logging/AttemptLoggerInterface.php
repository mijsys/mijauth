<?php
/**
 * MijAuth - Attempt Logger Interface
 *
 * @package   MijAuth
 * @author    MijagiKutasamoto
 * @license   MIT
 */

declare(strict_types=1);

namespace MijAuth\Logging;

/**
 * Interface for logging authorization attempts
 */
interface AttemptLoggerInterface
{
    /**
     * Log an authorization attempt
     *
     * @param array $context
     * @return void
     */
    public function logAttempt(array $context): void;
}
