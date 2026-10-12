require File.expand_path('test/test_helper', Dir.pwd)
require_relative '../../lib/redmine_oidc/oidc_client'

class OidcClientTest < ActiveSupport::TestCase
  def setup
    @issuer = 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0'
    Setting.plugin_redmine_oidc = {
      'issuer_url' => @issuer, 'client_identifier' => 'redmine-client', 'client_secret' => 'secret'
    }
    @client = RedmineOidc::OidcClient.new
    @key = OpenSSL::PKey::RSA.generate(2048)
    @jwk = JWT::JWK.new(@key, 'signing-key')
    @client.stubs(:discovery).returns(
      'issuer' => @issuer, 'jwks_uri' => 'https://issuer.example/keys',
      'authorization_endpoint' => 'https://issuer.example/authorize')
    @client.stubs(:fetch_json).with('https://issuer.example/keys').returns(
      'keys' => [JSON.parse(JSON.generate(@jwk.export))])
    @claims = {'iss' => @issuer, 'sub' => 'subject', 'aud' => 'redmine-client',
      'exp' => Time.now.to_i + 300, 'iat' => Time.now.to_i - 10,
      'nbf' => Time.now.to_i - 10, 'nonce' => 'nonce', 'preferred_username' => 'employee@example.org'}
  end

  def test_valid_signed_token
    assert_equal 'employee@example.org', verify['preferred_username']
  end

  def test_authorization_includes_nonce
    url = @client.authorization_url(redirect_uri: 'https://redmine.example/callback', state: 'state', nonce: 'nonce')
    assert_equal 'nonce', URI.decode_www_form(URI.parse(url).query).to_h['nonce']
  end

  def test_rejects_wrong_signature
    token = JWT.encode(@claims, OpenSSL::PKey::RSA.generate(2048), 'RS256', kid: 'signing-key')
    assert_raises(JWT::DecodeError) { @client.verified_id_token(token, nonce: 'nonce') }
  end

  def test_rejects_unsigned_and_hmac_tokens
    [['none', nil], ['HS256', 'secret']].each do |algorithm, key|
      token = JWT.encode(@claims, key, algorithm, kid: 'signing-key')
      assert_raises(JWT::DecodeError) { @client.verified_id_token(token, nonce: 'nonce') }
    end
  end

  def test_rejects_invalid_claims
    [{'iss' => 'https://other.example'}, {'aud' => 'other-client'},
     {'exp' => Time.now.to_i - 1}, {'nbf' => Time.now.to_i + 300},
     {'iat' => Time.now.to_i + 300}, {'nonce' => 'wrong'}, {'sub' => ''},
     {'aud' => ['redmine-client', 'other-client']}, {'azp' => 'other-client'}].each do |changes|
      assert_raises(JWT::DecodeError, changes.inspect) { verify(@claims.merge(changes)) }
    end
  end

  def test_rejects_missing_required_claims
    %w[iss sub aud exp iat nonce].each do |claim|
      assert_raises(JWT::DecodeError, claim) { verify(@claims.reject { |key, _| key == claim }) }
    end
  end

  def test_rejects_unknown_key_and_missing_token_or_nonce
    token = JWT.encode(@claims, @key, 'RS256', kid: 'unknown-key')
    assert_raises(JWT::DecodeError) { @client.verified_id_token(token, nonce: 'nonce') }
    assert_raises(JWT::DecodeError) { @client.verified_id_token(nil, nonce: 'nonce') }
    assert_raises(JWT::DecodeError) { @client.verified_id_token(token, nonce: nil) }
  end

  def test_rejects_discovery_issuer_mismatch_and_insecure_jwks
    @client.stubs(:discovery).returns('issuer' => 'https://other.example')
    assert_raises(JWT::DecodeError) { verify }
    @client.stubs(:discovery).returns('issuer' => @issuer, 'jwks_uri' => 'http://issuer.example/keys')
    assert_raises(JWT::DecodeError) { verify }
  end

  private

  def verify(claims = @claims)
    token = JWT.encode(claims, @key, 'RS256', kid: 'signing-key')
    @client.verified_id_token(token, nonce: 'nonce')
  end
end
