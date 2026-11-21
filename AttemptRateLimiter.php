<?php

/**
 * @package     Localzet SOCKS5
 * @link        https://github.com/localzet/SOCKS5
 *
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright © 2016-2026 Localzet Group. All rights reserved.
 * @license     https://www.gnu.org/licenses/agpl-3.0 GNU Affero General Public License v3.0
 */

declare(strict_types=1);

final class AttemptRateLimiter
{
    public const DEFAULT_MAX_TRACKED_IPS = 10_000;

    /** @var array<string, array{buckets: array<int, int>, total: int, lastSeenSecond: int}> */
    private array $attemptsByIp = [];

    public function __construct(
        private readonly int $maxAttemptsPerMinute,
        private readonly int $maxTrackedIps = self::DEFAULT_MAX_TRACKED_IPS,
    ) {
        if ($maxAttemptsPerMinute < 1 || $maxTrackedIps < 1) {
            throw new InvalidArgumentException('Rate limits must be positive.');
        }
    }

    public function allows(string $ip, float $now): bool
    {
        $currentSecond = (int)floor($now);

        if (isset($this->attemptsByIp[$ip])) {
            $state = $this->attemptsByIp[$ip];
            $firstActiveSecond = $currentSecond - 60;

            foreach ($state['buckets'] as $second => $count) {
                if ($second < $firstActiveSecond) {
                    $state['total'] -= $count;
                    unset($state['buckets'][$second]);
                }
            }

            $this->attemptsByIp[$ip] = $state;

            if ($state['total'] >= $this->maxAttemptsPerMinute) {
                return false;
            }

            $state['buckets'][$currentSecond] = ($state['buckets'][$currentSecond] ?? 0) + 1;
            $state['total']++;
            $state['lastSeenSecond'] = $currentSecond;

            unset($this->attemptsByIp[$ip]);
            $this->attemptsByIp[$ip] = $state;

            return true;
        }

        if (count($this->attemptsByIp) >= $this->maxTrackedIps) {
            $this->removeExpiredLeastRecentlyUsed($currentSecond);
        }

        if (count($this->attemptsByIp) >= $this->maxTrackedIps) {
            return false;
        }

        $this->attemptsByIp[$ip] = [
            'buckets' => [$currentSecond => 1],
            'total' => 1,
            'lastSeenSecond' => $currentSecond,
        ];

        return true;
    }

    private function removeExpiredLeastRecentlyUsed(int $currentSecond): void
    {
        $firstActiveSecond = $currentSecond - 60;

        while (($ip = array_key_first($this->attemptsByIp)) !== null) {
            if ($this->attemptsByIp[$ip]['lastSeenSecond'] >= $firstActiveSecond) {
                return;
            }

            unset($this->attemptsByIp[$ip]);
        }
    }
}
