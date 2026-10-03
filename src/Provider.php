<?php

namespace SocialiteProviders\AzureExternalIdentities;

use GuzzleHttp\RequestOptions;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;
use JsonException;
use SocialiteProviders\AzureExternalIdentities\Exceptions\InvalidStateException;
use SocialiteProviders\AzureExternalIdentities\Exceptions\TokenValidationException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

/**
 * Microsoft Entra External ID (CIAM) provider for Laravel Socialite.
 *
 * @see https://learn.microsoft.com/en-us/entra/external-id/customers/
 */
class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'AZURE_EI';

    /**
     * @var array<int, string>
     */
    protected $scopes = [
        'openid',
        'profile',
        'email',
        'offline_access',
    ];

    protected $scopeSeparator = ' ';

    protected bool $usesNonce = true;

    /**
     * Must remain untyped to match Laravel\Socialite\Two\AbstractProvider::$usesPKCE.
     *
     * @var bool
     */
    protected $usesPKCE = true;

    protected ?OpenIdConfigurationResolver $configurationResolver = null;

    protected ?IdTokenVerifier $idTokenVerifier = null;

    /**
     * @return array<int, string>
     */
    public static function additionalConfigKeys(): array
    {
        return [
            'authority',
            'tenant_subdomain',
            'tenant_id',
            'policy',
            'verify_id_token',
            'proxy',
        ];
    }

    public function redirect(): RedirectResponse
    {
        $state = null;

        if ($this->usesState()) {
            // keep the in-flight OAuth state
            $existingState = $this->request->session()->get('state');
            $state = is_string($existingState) && $existingState !== ''
                ? $existingState
                : $this->getState();
            $this->request->session()->put('state', $state);
        }

        if ($this->usesNonce()) {
            $existingNonce = $this->request->session()->get('nonce');
            $nonce = is_string($existingNonce) && $existingNonce !== ''
                ? $existingNonce
                : $this->generateNonce();
            $this->request->session()->put('nonce', $nonce);
        }

        if ($this->usesPKCE()) {
            // reuse an in-flight verifier so a double-hit on /redirect cannot
            // overwrite the session with a different value than code_challenge
            $verifier = $this->resolveCodeVerifier();
            $this->request->session()->put('code_verifier', $verifier);

            if (is_string($state) && $state !== '') {
                Cache::put($this->pkceCacheKey($state), $verifier, now()->addMinutes(10));
            }
        }

        return new RedirectResponse($this->getAuthUrl($state));
    }

    /**
     * @param  string  $code
     * @return array<string, mixed>
     */
    protected function getTokenFields($code): array
    {
        $fields = parent::getTokenFields($code);

        if ($this->usesPKCE()) {
            $verifier = $fields['code_verifier'] ?? null;

            if (! is_string($verifier) || $verifier === '') {
                $state = $this->request->input('state');
                if (is_string($state) && $state !== '') {
                    $cached = Cache::pull($this->pkceCacheKey($state));
                    if (is_string($cached) && $cached !== '') {
                        $fields['code_verifier'] = $cached;
                    }
                }
            } else {
                $state = $this->request->input('state');
                if (is_string($state) && $state !== '') {
                    Cache::forget($this->pkceCacheKey($state));
                }
            }
        }

        return $fields;
    }

    /**
     * prefer the existing session verifier so concurrent redirects stay consistent
     */
    protected function getCodeVerifier(): string
    {
        return $this->resolveCodeVerifier();
    }

    protected function resolveCodeVerifier(): string
    {
        $existing = $this->request->session()->get('code_verifier');

        if (is_string($existing) && $existing !== '') {
            return $existing;
        }

        return Str::random(96);
    }

    protected function pkceCacheKey(string $state): string
    {
        return 'azure-ei:pkce:' . $state;
    }

    /**
     * @return array<string, mixed>
     */
    public function getAccessTokenResponse($code): array
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS => ['Accept' => 'application/json'],
            RequestOptions::FORM_PARAMS => array_merge($this->getTokenFields($code), [
                'grant_type' => 'authorization_code',
            ]),
            RequestOptions::PROXY => $this->getConfig('proxy'),
        ]);

        try {
            return json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new TokenValidationException(
                'Token endpoint returned invalid JSON: ' . $exception->getMessage(),
                previous: $exception
            );
        }
    }

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException('The OAuth state parameter is invalid.');
        }

        $tokenResponse = $this->getAccessTokenResponse($this->request->input('code'));

        if (! isset($tokenResponse['id_token']) || ! is_string($tokenResponse['id_token'])) {
            throw new TokenValidationException('Token response did not include an ID token.');
        }

        $claims = $this->resolveIdTokenClaims($tokenResponse['id_token']);

        if ($this->usesNonce()) {
            $this->request->session()->forget('nonce');
        }

        if ($this->missingEmail($claims) && isset($tokenResponse['access_token'])) {
            $claims = array_merge(
                $claims,
                $this->getUserByToken($tokenResponse['access_token'])
            );
        }

        $this->user = $this->mapUserToObject($claims);

        return $this->user
            ->setToken($tokenResponse['access_token'] ?? null)
            ->setRefreshToken($tokenResponse['refresh_token'] ?? null)
            ->setExpiresIn($tokenResponse['expires_in'] ?? null);
    }

    /**
     * Build the logout URL (e.g. https://{subdomain}.ciamlogin.com/{tenant_id}/oauth2/v2.0/logout).
     */
    public function getLogoutUrl(?string $postLogoutRedirectUri = null): string
    {
        $logoutUrl = $this->getBaseAuthority() . '/oauth2/v2.0/logout';

        if ($postLogoutRedirectUri === null) {
            return $logoutUrl;
        }

        return $logoutUrl . '?' . http_build_query([
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
        ], '', '&', $this->encodingType);
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->getAuthorizationEndpoint(), $state);
    }

    protected function getTokenUrl(): string
    {
        return $this->getOpenIdConfiguration()['token_endpoint'];
    }

    /**
     * @return array<string, mixed>
     */
    protected function getUserByToken($token): array
    {
        $userInfoEndpoint = $this->getOpenIdConfiguration()['userinfo_endpoint'] ?? null;

        if (! is_string($userInfoEndpoint) || $userInfoEndpoint === '') {
            return [];
        }

        $response = $this->getHttpClient()->get($userInfoEndpoint, [
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
                'Authorization' => 'Bearer ' . $token,
            ],
            RequestOptions::PROXY => $this->getConfig('proxy'),
        ]);

        return json_decode((string) $response->getBody(), true) ?? [];
    }

    /**
     * @param  array<string, mixed>  $user
     */
    protected function mapUserToObject(array $user): User
    {
        return (new User())->setRaw($user)->map([
            'id' => $user['oid'] ?? $user['sub'] ?? null,
            'nickname' => $user['preferred_username'] ?? null,
            'name' => $user['name'] ?? null,
            'email' => $this->resolveEmail($user),
            'avatar' => null,
            'given_name' => $user['given_name'] ?? null,
            'family_name' => $user['family_name'] ?? null,
            'tenant_id' => $user['tid'] ?? null,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    protected function getCodeFields($state = null): array
    {
        $fields = parent::getCodeFields($state);

        if ($this->usesNonce()) {
            $fields['nonce'] = $this->getSessionNonce();
        }

        if ($policy = $this->getPolicy()) {
            $fields['p'] = $policy;
        }

        return $fields;
    }

    /**
     * @return array<string, mixed>
     */
    protected function getOpenIdConfiguration(): array
    {
        return $this->configurationResolver()->resolve($this->getAuthority());
    }

    /**
     * @return array<string, mixed>
     */
    protected function resolveIdTokenClaims(string $idToken): array
    {
        if ($this->shouldVerifyIdToken()) {
            $configuration = $this->getOpenIdConfiguration();

            if (! isset($configuration['jwks_uri']) || ! is_string($configuration['jwks_uri'])) {
                throw new TokenValidationException('OpenID configuration is missing a JWKS URI.');
            }

            $jwks = $this->configurationResolver()->resolveJwks($configuration['jwks_uri']);

            // Use the issuer published in the OIDC discovery document as the
            // expected value — this is the authority-canonical issuer string.
            $expectedIssuer = isset($configuration['issuer']) && is_string($configuration['issuer'])
                ? $configuration['issuer']
                : null;

            return $this->idTokenVerifier()->verify(
                idToken: $idToken,
                clientId: $this->clientId,
                expectedNonce: $this->getSessionNonce(),
                jwks: $jwks,
                validateNonce: $this->usesNonce(),
                expectedIssuer: $expectedIssuer,
            );
        }

        $claims = $this->idTokenVerifier()->decodeWithoutVerification($idToken);

        if ($this->usesNonce()) {
            $sessionNonce = $this->getSessionNonce();

            if (($claims['nonce'] ?? null) !== $sessionNonce) {
                throw new TokenValidationException('The ID token contains an invalid nonce.');
            }
        }

        return $claims;
    }

    protected function getAuthorizationEndpoint(): string
    {
        return $this->getOpenIdConfiguration()['authorization_endpoint'];
    }

    /**
     * Get the full authority URL (e.g. https://{subdomain}.ciamlogin.com/{tenant_id}/v2.0).
     */
    protected function getAuthority(): string
    {
        return $this->getBaseAuthority() . '/v2.0';
    }

    /**
     * Get the base authority URL (e.g. https://{subdomain}.ciamlogin.com/{tenant_id}).
     */
    protected function getBaseAuthority(): string
    {
        $authority = $this->getConfig('authority');

        if (is_string($authority) && $authority !== '') {
            $trimmed = rtrim($authority, '/');

            return preg_replace('/\/v2\.0$/i', '', $trimmed) ?? $trimmed;
        }

        $tenantSubdomain = $this->getConfig('tenant_subdomain');
        $tenantId = $this->getConfig('tenant_id');

        if (! is_string($tenantSubdomain) || $tenantSubdomain === '') {
            throw new TokenValidationException('The tenant_subdomain configuration value is required.');
        }

        if (! is_string($tenantId) || $tenantId === '') {
            throw new TokenValidationException('The tenant_id configuration value is required.');
        }

        return sprintf(
            'https://%s.ciamlogin.com/%s',
            $tenantSubdomain,
            $tenantId
        );
    }

    protected function getPolicy(): ?string
    {
        $policy = $this->getConfig('policy');

        return is_string($policy) && $policy !== '' ? $policy : null;
    }

    protected function shouldVerifyIdToken(): bool
    {
        return (bool) $this->getConfig('verify_id_token', true);
    }

    protected function usesNonce(): bool
    {
        return $this->usesNonce;
    }

    protected function generateNonce(): string
    {
        return Str::random(40);
    }

    protected function getSessionNonce(): ?string
    {
        $nonce = $this->request->session()->get('nonce');

        return is_string($nonce) && $nonce !== '' ? $nonce : null;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    protected function missingEmail(array $claims): bool
    {
        return $this->resolveEmail($claims) === null;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    protected function resolveEmail(array $claims): ?string
    {
        if (isset($claims['email']) && is_string($claims['email']) && $claims['email'] !== '') {
            return $claims['email'];
        }

        if (isset($claims['emails']) && is_array($claims['emails'])) {
            foreach ($claims['emails'] as $email) {
                if (is_string($email) && $email !== '') {
                    return $email;
                }
            }
        }

        if (isset($claims['preferred_username']) && is_string($claims['preferred_username']) && str_contains($claims['preferred_username'], '@')) {
            return $claims['preferred_username'];
        }

        return null;
    }

    protected function configurationResolver(): OpenIdConfigurationResolver
    {
        return $this->configurationResolver ??= new OpenIdConfigurationResolver(
            $this->getHttpClient(),
            Cache::store()
        );
    }

    protected function idTokenVerifier(): IdTokenVerifier
    {
        return $this->idTokenVerifier ??= new IdTokenVerifier();
    }
}
