<?php

/**
 * @package     Localzet SOCKS5 tests
 * @link        https://github.com/localzet/SOCKS5
 *
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright © 2016-2026 Localzet Group. All rights reserved.
 * @license     https://www.gnu.org/licenses/agpl-3.0 GNU Affero General Public License v3.0
 */

declare(strict_types=1);

require dirname(__DIR__) . '/AttemptRateLimiter.php';

function expectRateLimit(bool $expected, bool $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message);
    }
}

$limiter = new AttemptRateLimiter(2, 2);
expectRateLimit(true, $limiter->allows('192.0.2.1', 100.1), 'First attempt must be accepted.');
expectRateLimit(true, $limiter->allows('192.0.2.1', 100.2), 'Second attempt must be accepted.');
expectRateLimit(false, $limiter->allows('192.0.2.1', 100.3), 'Per-IP attempt limit must be enforced.');

$limiter = new AttemptRateLimiter(10, 2);
expectRateLimit(true, $limiter->allows('192.0.2.1', 200.1), 'First tracked IP must be accepted.');
expectRateLimit(true, $limiter->allows('192.0.2.2', 200.2), 'Second tracked IP must be accepted.');
expectRateLimit(false, $limiter->allows('192.0.2.3', 201.0), 'New IP must be rejected while active tracking is full.');
expectRateLimit(true, $limiter->allows('192.0.2.1', 201.1), 'Full tracking must preserve active IP state.');
expectRateLimit(false, $limiter->allows('192.0.2.3', 260.9), 'The oldest partial second must remain counted at the boundary.');
expectRateLimit(true, $limiter->allows('192.0.2.3', 261.0), 'Expired IP state must be reclaimed for a new address.');

$limiter = new AttemptRateLimiter(1, 2);
expectRateLimit(true, $limiter->allows('192.0.2.4', 300.9), 'Initial boundary attempt must be accepted.');
expectRateLimit(false, $limiter->allows('192.0.2.4', 360.99), 'Bucket expiry must not happen before the 60-second boundary.');
expectRateLimit(true, $limiter->allows('192.0.2.4', 361.0), 'Expired bucket must stop counting after its full second elapses.');

echo "SOCKS5 attempt rate limiter tests passed.\n";
