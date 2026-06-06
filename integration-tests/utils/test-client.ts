/**
 * Test HTTP Client with Authentication Helpers
 *
 * Provides a unified HTTP client for integration tests with built-in
 * authentication, session management, and error handling.
 */

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  headers?: Record<string, string>;
  body?: unknown;
  credentials?: 'include' | 'omit' | 'same-origin';
}

export interface AuthCredentials {
  customer_id?: string;
  user_id?: string;
  token?: string;
  publicKey?: string;
  secretKey?: string;
  sessionToken?: string;
  csrfToken?: string;
}

export interface ServiceEndpoints {
  verifierPortal: string;
  hostedBackend: string;
  issuerApi: string;
  creditManagement: string;
  verifierApi: string;
}

/**
 * Test HTTP Client
 */
export class TestClient {
  private baseUrls: ServiceEndpoints;
  private defaultHeaders: Record<string, string>;
  private credentials?: AuthCredentials;
  private sessionCookies: Map<string, string> = new Map();

  constructor(endpoints?: Partial<ServiceEndpoints>) {
    this.baseUrls = {
      verifierPortal: endpoints?.verifierPortal || 'http://localhost:8787',
      hostedBackend: endpoints?.hostedBackend || 'http://localhost:8788',
      issuerApi: endpoints?.issuerApi || 'http://localhost:8789',
      creditManagement: endpoints?.creditManagement || 'http://localhost:8790',
      verifierApi: endpoints?.verifierApi || 'http://localhost:8791',
    };

    this.defaultHeaders = {
      'Content-Type': 'application/json',
      'User-Agent': 'Provii-Integration-Tests/1.0',
    };
  }

  /**
   * Set authentication credentials for subsequent requests
   */
  setAuth(credentials: AuthCredentials): this {
    this.credentials = credentials;
    return this;
  }

  /**
   * Clear authentication credentials
   */
  clearAuth(): this {
    this.credentials = undefined;
    this.sessionCookies.clear();
    return this;
  }

  /**
   * Make an HTTP request to a service
   */
  async request(
    service: keyof ServiceEndpoints,
    path: string,
    options: RequestOptions = {}
  ): Promise<Response> {
    const url = new URL(path, this.baseUrls[service]);
    const headers = { ...this.defaultHeaders, ...options.headers };

    // Add authentication headers
    if (this.credentials) {
      if (this.credentials.token && this.credentials.customer_id) {
        // HMAC authentication (verifier portal, provii-credit-management)
        headers['Authorization'] = `Bearer ${this.credentials.customer_id}:${this.credentials.token}`;
      } else if (this.credentials.publicKey) {
        // Public key authentication (provii-verifier)
        headers['X-Public-Key'] = this.credentials.publicKey;
        if (this.credentials.secretKey) {
          // Sign request if secret key provided
          const signature = await this.signRequest(
            options.method || 'GET',
            path,
            options.body,
            this.credentials.secretKey
          );
          headers['X-Signature'] = signature;
        }
      }

      if (this.credentials.csrfToken) {
        headers['X-CSRF-Token'] = this.credentials.csrfToken;
      }
    }

    // Add session cookies
    if (this.sessionCookies.size > 0) {
      const cookieHeader = Array.from(this.sessionCookies.entries())
        .map(([name, value]) => `${name}=${value}`)
        .join('; ');
      headers['Cookie'] = cookieHeader;
    }

    const fetchOptions: RequestInit = {
      method: options.method || 'GET',
      headers,
      credentials: options.credentials || 'include',
    };

    if (options.body && (options.method === 'POST' || options.method === 'PUT' || options.method === 'PATCH')) {
      fetchOptions.body = JSON.stringify(options.body);
    }

    const response = await fetch(url.toString(), fetchOptions);

    // Extract and store session cookies from response
    const setCookie = response.headers.get('Set-Cookie');
    if (setCookie) {
      this.parseAndStoreCookies(setCookie);
    }

    return response;
  }

  /**
   * Make a GET request
   */
  async get(service: keyof ServiceEndpoints, path: string, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<Response> {
    return this.request(service, path, { ...options, method: 'GET' });
  }

  /**
   * Make a POST request
   */
  async post(service: keyof ServiceEndpoints, path: string, body: unknown, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<Response> {
    return this.request(service, path, { ...options, method: 'POST', body });
  }

  /**
   * Make a PUT request
   */
  async put(service: keyof ServiceEndpoints, path: string, body: unknown, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<Response> {
    return this.request(service, path, { ...options, method: 'PUT', body });
  }

  /**
   * Make a DELETE request
   */
  async delete(service: keyof ServiceEndpoints, path: string, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<Response> {
    return this.request(service, path, { ...options, method: 'DELETE' });
  }

  /**
   * Parse JSON response with error handling
   */
  async parseJson<T = unknown>(response: Response): Promise<T> {
    const text = await response.text();
    if (!text) {
      throw new Error('Empty response body');
    }
    try {
      return JSON.parse(text) as T;
    } catch (error) {
      throw new Error(`Failed to parse JSON: ${text.substring(0, 200)}`);
    }
  }

  /**
   * Sign a request using HMAC-SHA256
   */
  private async signRequest(
    method: string,
    path: string,
    body: unknown,
    secretKey: string
  ): Promise<string> {
    // Canonical message format: METHOD:PATH:BODY_JSON_OR_EMPTY
    const bodyStr = body ? JSON.stringify(body) : '';
    const canonicalMessage = `${method.toUpperCase()}:${path}:${bodyStr}`;

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secretKey),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(canonicalMessage)
    );

    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Parse and store cookies from Set-Cookie header
   */
  private parseAndStoreCookies(setCookieHeader: string): void {
    // Simple cookie parser (handles basic cases)
    const cookies = setCookieHeader.split(',').map(c => c.trim());

    for (const cookie of cookies) {
      const parts = cookie.split(';')[0].trim();
      const [name, value] = parts.split('=');
      if (name && value) {
        this.sessionCookies.set(name, value);
      }
    }
  }

  /**
   * Helper: Login to verifier-portal and get session + CSRF token
   */
  async loginVerifierPortal(customer_id: string, token: string): Promise<{ sessionToken: string; csrfToken: string }> {
    const response = await this.post('verifierPortal', '/api/v1/login', {
      customer_id,
      token,
    });

    if (!response.ok) {
      const error = await this.parseJson(response);
      throw new Error(`Login failed: ${JSON.stringify(error)}`);
    }

    const data = await this.parseJson<{
      session_token: string;
      csrf_token: string;
    }>(response);

    // Store credentials for subsequent requests
    this.setAuth({
      customer_id,
      token,
      sessionToken: data.session_token,
      csrfToken: data.csrf_token,
    });

    return {
      sessionToken: data.session_token,
      csrfToken: data.csrf_token,
    };
  }

  /**
   * Helper: Create a hosted challenge
   */
  async createHostedChallenge(params: {
    publicKey: string;
    secretKey?: string;
    origin: string;
    minimum_age: number;
    code_challenge: string;
  }): Promise<{
    session_id: string;
    challenge_id: string;
    qr_code_url: string;
    challenge_code: string;
    expires_at: number;
  }> {
    this.setAuth({
      publicKey: params.publicKey,
      secretKey: params.secretKey,
    });

    const response = await this.post('hostedBackend', '/v1/hosted/challenge', {
      origin: params.origin,
      minimum_age: params.minimum_age,
      code_challenge: params.code_challenge,
      code_challenge_method: 'S256',
    });

    if (!response.ok) {
      const error = await this.parseJson(response);
      throw new Error(`Challenge creation failed: ${JSON.stringify(error)}`);
    }

    return this.parseJson(response);
  }

  /**
   * Helper: Check hosted session status
   */
  async checkHostedStatus(session_id: string): Promise<{
    status: string;
    challenge_id: string;
    expires_at: number;
    verified_at?: number;
  }> {
    const response = await this.get('hostedBackend', `/v1/hosted/status/${session_id}`);

    if (!response.ok) {
      const error = await this.parseJson(response);
      throw new Error(`Status check failed: ${JSON.stringify(error)}`);
    }

    return this.parseJson(response);
  }

  /**
   * Helper: Redeem hosted session with code_verifier
   */
  async redeemHostedSession(session_id: string, code_verifier: string): Promise<{
    verified: boolean;
    age: number;
    session_token?: string;
  }> {
    const response = await this.post('hostedBackend', `/v1/hosted/redeem/${session_id}`, {
      code_verifier,
    });

    if (!response.ok) {
      const error = await this.parseJson(response);
      throw new Error(`Redemption failed: ${JSON.stringify(error)}`);
    }

    return this.parseJson(response);
  }

  /**
   * Helper: Get credit balance
   */
  async getCreditBalance(customer_id: string): Promise<{
    balance_credits: number;
    reserved_credits: number;
    total_verifications: number;
  }> {
    const response = await this.get('verifierPortal', '/api/v1/balance');

    if (!response.ok) {
      const error = await this.parseJson(response);
      throw new Error(`Balance check failed: ${JSON.stringify(error)}`);
    }

    return this.parseJson(response);
  }

  /**
   * Helper: Deduct credits
   */
  async deductCredits(params: {
    customer_id: string;
    verification_id: string;
    origin: string;
    credits: number;
  }): Promise<{
    balance_credits: number;
    reserved_credits: number;
  }> {
    const response = await this.post('creditManagement', '/v1/credits/deduct', {
      customer_id: params.customer_id,
      verification_id: params.verification_id,
      origin: params.origin,
      credits: params.credits,
    });

    if (!response.ok) {
      const error = await this.parseJson(response);
      throw new Error(`Credit deduction failed: ${JSON.stringify(error)}`);
    }

    return this.parseJson(response);
  }

  /**
   * Helper: Wait for condition with timeout
   */
  async waitFor<T>(
    fn: () => Promise<T>,
    predicate: (result: T) => boolean,
    options: { timeout?: number; interval?: number } = {}
  ): Promise<T> {
    const timeout = options.timeout || 30000;
    const interval = options.interval || 500;
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      try {
        const result = await fn();
        if (predicate(result)) {
          return result;
        }
      } catch (error) {
        // Ignore errors and keep polling
      }
      await new Promise(resolve => setTimeout(resolve, interval));
    }

    throw new Error(`waitFor timeout after ${timeout}ms`);
  }
}

/**
 * Create a test client instance
 */
export function createTestClient(endpoints?: Partial<ServiceEndpoints>): TestClient {
  return new TestClient(endpoints);
}
