require 'singleton'
require 'net/http'
require 'uri'
require 'json'
require 'jwt'
require 'openssl'
require 'active_support/core_ext/hash/indifferent_access'

class KeycloakTokenService
  include Singleton

  class VerificationError < StandardError
    attr_reader :status

    def initialize(message, status = 401)
      super(message)
      @status = status
    end
  end

  FIVE_MINUTES = 5 * 60

  def configured?
    keycloak_config.present?
  end

  def decode(token)
    raise VerificationError.new('Keycloak is not configured.', 500) unless configured?

    options = {
      algorithms: ['RS256'],
      verify_expiration: true,
      leeway: 10,
      verify_iss: true,
      iss: issuer,
      verify_aud: true,
      aud: expected_audiences
    }

    if public_key
      decoded = JWT.decode(token, public_key, true, options)
    else
      decoded = JWT.decode(token, nil, true, options.merge(jwks: jwks_loader))
    end

    decoded.first.with_indifferent_access
  rescue JWT::ExpiredSignature
    raise VerificationError.new('Access token expired.', 401)
  rescue JWT::InvalidAudError
    raise VerificationError.new('Token audience is invalid.', 401)
  rescue JWT::DecodeError => e
    raise VerificationError.new("Invalid access token: #{e.message}", 401)
  rescue OpenSSL::PKey::RSAError => e
    raise VerificationError.new("Invalid Keycloak public key: #{e.message}", 500)
  rescue SocketError, Errno::ECONNREFUSED, Timeout::Error => e
    raise VerificationError.new("Unable to reach Keycloak JWKS endpoint: #{e.message}", 503)
  end

  private

  def keycloak_config
    @keycloak_config ||= Doubtfire::Application.config.keycloak
  end

  def issuer
    @issuer ||= begin
      base = keycloak_config[:url]
      base = base.end_with?('/') ? base : "#{base}/"
      "#{base}realms/#{keycloak_config[:realm]}"
    end
  end

  def jwks_uri
    @jwks_uri ||= URI.parse("#{issuer}/protocol/openid-connect/certs")
  end

  def expected_audiences
    @expected_audiences ||= begin
      raw = keycloak_config[:audience]
      Array(raw.is_a?(String) ? raw.split(/\s*,\s*/) : raw).presence || ['doubtfire-api']
    end
  end

  def public_key
    @public_key ||= begin
      key_body = keycloak_config[:public_key]
      return nil if key_body.blank?

      pem = if key_body.include?('BEGIN PUBLIC KEY')
              key_body
            else
              formatted = key_body.gsub('\n', '').gsub('\r', '')
              chunks = formatted.scan(/.{1,64}/)
              "-----BEGIN PUBLIC KEY-----\n#{chunks.join("\n")}\n-----END PUBLIC KEY-----\n"
            end
      OpenSSL::PKey::RSA.new(pem)
    end
  end

  def jwks_loader
    lambda do |options|
      kid = options[:kid]
      jwk = locate_jwk(kid)
      raise VerificationError.new('Unable to locate matching JWK for token.', 401) unless jwk
      JWT::JWK.import(jwk).public_key
    end
  end

  def locate_jwk(kid)
    keys = fetch_jwks['keys'] || []
    match = keys.find { |key| key['kid'] == kid }
    return match if match

    @jwks_cache = nil
    keys = fetch_jwks['keys'] || []
    keys.find { |key| key['kid'] == kid }
  end

  def fetch_jwks
    if @jwks_cache.nil? || jwks_cache_stale?
      response = Net::HTTP.get_response(jwks_uri)
      unless response.is_a?(Net::HTTPSuccess)
        raise VerificationError.new("Failed to download Keycloak JWKS (#{response.code}).", 503)
      end

      @jwks_cache = JSON.parse(response.body)
      @jwks_cached_at = Time.zone.now
    end

    @jwks_cache
  end

  def jwks_cache_stale?
    return true if @jwks_cached_at.nil?

    Time.zone.now.to_i - @jwks_cached_at.to_i > FIVE_MINUTES
  end
end
