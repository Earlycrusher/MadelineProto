<?php

declare(strict_types=1);

/**
 * MTProto Auth key.
 *
 * This file is part of MadelineProto.
 * MadelineProto is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 * MadelineProto is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU General Public License along with MadelineProto.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 * @author    Daniil Gentili <daniil@daniil.it>
 * @copyright 2016-2025 Daniil Gentili <daniil@daniil.it>
 * @license   https://opensource.org/licenses/AGPL-3.0 AGPLv3
 * @link https://docs.madelineproto.xyz MadelineProto documentation
 */

namespace danog\MadelineProto\MTProto;

use danog\MadelineProto\Reactive\Publisher;
use danog\MadelineProto\Reactive\Subscriber;
use JsonSerializable;
use Webmozart\Assert\Assert;

/**
 * MTProto auth key.
 *
 * @internal
 */
final class NewAuthKey
{
    private ?string $authKey = null;
    private ?string $id = null;
    private ?string $tempAuthKey = null;
    private ?string $tempId = null;
    public ?string $serverSalt = null;

    private ConnectionState $state = ConnectionState::UNENCRYPTED;
    /** @var Publisher<ConnectionState> */
    public readonly Publisher $connectionState;
    
    public function __construct(
        public readonly bool $isMedia,
        public readonly bool $isCdn,
    )
    {
        $this->connectionState->publish($this->state);
    }

    public function getState(): ConnectionState
    {
        return $this->state;
    }
    public function setAuthKey(?string $authKey): void
    {
        $this->authKey = $authKey;
        if ($authKey === null) {
            $this->id = null;
        } else {
            $this->id = substr(sha1($authKey, true), -8);
        }
    }
    public function setTempAuthKey(?string $authKey): void
    {
        $this->tempAuthKey = $authKey;
        if ($authKey === null) {
            $this->tempId = null;
            $this->state = ConnectionState::UNENCRYPTED;
        } else {
            $this->tempId = substr(sha1($authKey, true), -8);
            $this->state = ConnectionState::ENCRYPTED_NOT_INITED;
        }
        $this->connectionState->publish($this->state);
    }
    /**
     * Get auth key.
     */
    public function getAuthKey(): ?string
    {
        return $this->authKey;
    }
    /**
     * Get auth key ID.
     */
    public function getID(): ?string
    {
        return $this->id;
    }
    /**
     * Get auth key.
     */
    public function getTempAuthKey(): ?string
    {
        return $this->tempAuthKey;
    }
    /**
     * Get auth key ID.
     */
    public function getTempID(): ?string
    {
        return $this->tempId;
    }

    public function init(): void {
        Assert::eq($this->state, ConnectionState::ENCRYPTED_NOT_INITED);
        $this->state = ConnectionState::ENCRYPTED_NOT_BOUND;
        $this->connectionState->publish($this->state);
    }
    public function bind(): void {
        Assert::eq($this->state, ConnectionState::ENCRYPTED_NOT_BOUND);
        $this->state = ConnectionState::ENCRYPTED_NOT_AUTHED;
        $this->connectionState->publish($this->state);
    }
    public function authorize(): void {
        Assert::eq($this->state, ConnectionState::ENCRYPTED_NOT_AUTHED);
        $this->state = ConnectionState::ENCRYPTED;
        $this->connectionState->publish($this->state);
    }
}
