<?php

declare(strict_types=1);

final class HandshakeBuffer
{
    private string $buffer = '';

    public function append(string $data): void
    {
        if (strlen($this->buffer) + strlen($data) > 65_536) {
            throw new UnexpectedValueException('SOCKS handshake buffer limit exceeded');
        }
        $this->buffer .= $data;
    }

    public function take(int $stage): ?string
    {
        $size = strlen($this->buffer);
        if ($stage === 0) {
            if ($size < 2) {
                return null;
            }
            if (ord($this->buffer[0]) !== 5 || ord($this->buffer[1]) === 0) {
                throw new UnexpectedValueException('Invalid SOCKS greeting');
            }
            $length = 2 + ord($this->buffer[1]);
        } elseif ($stage === 1) {
            if ($size < 2) {
                return null;
            }
            $username = ord($this->buffer[1]);
            if (ord($this->buffer[0]) !== 1 || $username === 0) {
                throw new UnexpectedValueException('Invalid SOCKS authentication');
            }
            if ($size < 3 + $username) {
                return null;
            }
            $password = ord($this->buffer[2 + $username]);
            if ($password === 0) {
                throw new UnexpectedValueException('Empty SOCKS password');
            }
            $length = 3 + $username + $password;
        } elseif ($stage === 2) {
            if ($size < 4) {
                return null;
            }
            if (ord($this->buffer[0]) !== 5 || ord($this->buffer[2]) !== 0) {
                throw new UnexpectedValueException('Invalid SOCKS request');
            }
            $type = ord($this->buffer[3]);
            if ($type === 3 && $size < 5) {
                return null;
            }
            $length = match ($type) {
                1 => 10,
                4 => 22,
                3 => 7 + ord($this->buffer[4]),
                default => throw new UnexpectedValueException('Unknown SOCKS address type'),
            };
            if ($type === 3 && ord($this->buffer[4]) === 0) {
                throw new UnexpectedValueException('Empty SOCKS hostname');
            }
        } else {
            return null;
        }
        if ($size < $length) {
            return null;
        }
        $packet = substr($this->buffer, 0, $length);
        if ($stage === 2 && ord($packet[3]) === 3 &&
            filter_var(substr($packet, 5, ord($packet[4])), FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new UnexpectedValueException('Invalid SOCKS hostname');
        }
        $this->buffer = substr($this->buffer, $length);
        return $packet;
    }

    public function drain(): string
    {
        $data = $this->buffer;
        $this->buffer = '';
        return $data;
    }
}
