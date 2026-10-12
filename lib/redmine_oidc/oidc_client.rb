require 'net/http'
require 'json'
require 'uri'
require 'jwt'

module RedmineOidc
  class OidcClient
    TIMEOUT = 10

    attr_reader :issuer_url, :client_id, :client_secret, :scopes

    def initialize
      settings = Setting.plugin_redmine_oidc || {}
      @issuer_url    = settings['issuer_url'].to_s.chomp('/')
      @client_id     = settings['client_identifier'].to_s
      @client_secret = settings['client_secret'].to_s
      @scopes        = settings['scopes'].to_s.presence || 'openid email profile'
    end

    def configured?
      @issuer_url.present? && @client_id.present? && @client_secret.present?
    end

    def discovery
      @discovery ||= fetch_json("#{@issuer_url}/.well-known/openid-configuration")
    end

    def entra_id?
      uri = URI.parse(@issuer_url)
      uri.scheme == 'https' && uri.host == 'login.microsoftonline.com'
    end

    def authorization_url(redirect_uri:, state:, nonce: nil)
      params = {
        response_type: 'code',
        client_id:     @client_id,
        redirect_uri:  redirect_uri,
        scope:         @scopes,
        state:         state
      }
      params[:nonce] = nonce if nonce
      "#{discovery['authorization_endpoint']}?#{URI.encode_www_form(params)}"
    end

    # Only use claims after verifying the signature with the provider's JWKS.
    # Entra must use a tenant-specific v2 issuer (not common/organizations).
    def verified_id_token(token, nonce:)
      raise JWT::DecodeError, 'Missing ID token or nonce' if token.to_s.empty? || nonce.to_s.empty?
      raise JWT::DecodeError, 'Discovery issuer mismatch' unless discovery['issuer'] == @issuer_url
      jwks_uri = URI.parse(discovery.fetch('jwks_uri'))
      raise JWT::DecodeError, 'JWKS must use HTTPS' unless jwks_uri.scheme == 'https'

      jwks = fetch_json(jwks_uri.to_s)
      signing_keys = jwks.fetch('keys').select do |key|
        key['kty'] == 'RSA' && (!key['use'] || key['use'] == 'sig') &&
          (!key['alg'] || key['alg'] == 'RS256') &&
          (!key['key_ops'] || key['key_ops'].include?('verify'))
      end
      claims, = JWT.decode(token, nil, true,
        algorithms: ['RS256'], jwks: {keys: signing_keys},
        iss: @issuer_url, verify_iss: true,
        aud: @client_id, verify_aud: true,
        verify_expiration: true, verify_not_before: true, verify_iat: true,
        required_claims: %w[iss sub aud exp iat nonce])
      raise JWT::DecodeError, 'Nonce mismatch' unless claims['nonce'] == nonce
      audiences = Array(claims['aud'])
      if (audiences.length > 1 || claims.key?('azp')) && claims['azp'] != @client_id
        raise JWT::DecodeError, 'Authorized party mismatch'
      end
      raise JWT::DecodeError, 'Missing subject' unless claims['sub'].is_a?(String) && !claims['sub'].empty?
      claims
    end

    def exchange_code(code, redirect_uri:)
      uri = URI.parse(discovery['token_endpoint'])
      body = {
        grant_type:    'authorization_code',
        code:          code,
        redirect_uri:  redirect_uri,
        client_id:     @client_id,
        client_secret: @client_secret
      }
      response = post_request(uri, body)
      JSON.parse(response.body)
    end

    def userinfo(access_token)
      uri = URI.parse(discovery['userinfo_endpoint'])
      request = Net::HTTP::Get.new(uri)
      request['Authorization'] = "Bearer #{access_token}"
      response = execute_request(uri, request)
      JSON.parse(response.body)
    end

    private

    def fetch_json(url)
      uri = URI.parse(url)
      request = Net::HTTP::Get.new(uri)
      request['Accept'] = 'application/json'
      response = execute_request(uri, request)
      JSON.parse(response.body)
    end

    def post_request(uri, body)
      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'application/x-www-form-urlencoded'
      request['Accept'] = 'application/json'
      request.body = URI.encode_www_form(body)
      execute_request(uri, request)
    end

    def execute_request(uri, request)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = (uri.scheme == 'https')
      http.open_timeout = TIMEOUT
      http.read_timeout = TIMEOUT
      http.request(request)
    end
  end
end
