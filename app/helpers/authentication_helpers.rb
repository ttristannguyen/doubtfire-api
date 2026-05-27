require 'onelogin/ruby-saml'
require 'net/http'
require 'cgi'

#
# The AuthenticationHelpers include functions to check if the user
# is authenticated and to fetch the current user.
#
# This is used by the grape api.
#
module AuthenticationHelpers
  module_function

  #
  # Checks if the requested user is authenticated.
  # Reads details from the params fetched from the caller context.
  #
  def authenticated?(token_type = :general)
    auth_param = headers['auth-token'] || headers['Auth-Token'] || params['authToken'] || headers['Auth_Token'] || headers['auth_token'] || params['auth_token'] || params['Auth_Token']
    user_param = headers['username'] || headers['Username'] || params['username']

    # Check for valid auth token  and username in request header
    user = current_user

    # Authenticate from header or params
    if auth_param.present? && user_param.present? && user.present?
      # Get the list of tokens for a user
      token = user.token_for_text?(auth_param, token_type)
    end

    # Check user by token
    if user.present? && token.present?
      if token.auth_token_expiry > Time.zone.now
        logger.info("Authenticated #{user.username} from #{request.ip}")
        return true
      end

      # Token is timed out - destroy it and throw error
      logger.info("Timing out token for #{user.username} from #{request.ip}")
      token.destroy!
      error!({ error: 'Authentication token expired.' }, 419)
    elsif token.present?
      logger.info("Error logging in for #{user_param} / #{auth_param} from #{request.ip}")

      # Add random delay then fail
      sleep(rand(200..399) / 1000.0)
      error!({ error: 'Could not authenticate with token. Username or Token invalid.' }, 419)
    else
      error!({ error: 'No authentication details provided. Authentication is required to access this resource.' }, 419)
    end
  end

  #
  # Get the current user either from warden or from the header
  #
  def current_user
    username = headers['username'] || headers['Username'] || params['username']
    User.eager_load(:role, :auth_tokens).find_by(username: username)
  end

  #
  # Add the required auth_token to each of the routes for the provided
  # Grape::API.
  #
  def add_auth_to(service)
    service.routes.each do |route|
      options = route.instance_variable_get('@options')
      next if options[:params]['Auth_Token']

      options[:params]['Username'] = {
        required: true,
        type: 'String',
        in: 'header',
        desc: 'Username'
      }
      options[:params]['Auth_Token'] = {
        required: true,
        type: 'String',
        in: 'header',
        desc: 'Authentication token'
      }
    end
  end

  #
  # Returns the SAML2.0 settings object using information provided as env variables
  #
  def saml_settings
    return unless saml_auth?

    metadata_url = Doubtfire::Application.config.saml[:SAML_metadata_url] || nil

    if metadata_url
      idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
      settings = idp_metadata_parser.parse_remote(metadata_url, timeout: 5)
    else
      settings = OneLogin::RubySaml::Settings.new
      settings.idp_cert                     = Doubtfire::Application.config.saml[:idp_sso_cert]
      settings.name_identifier_format       = Doubtfire::Application.config.saml[:idp_name_identifier_format]
    end
    settings.assertion_consumer_service_url = Doubtfire::Application.config.saml[:assertion_consumer_service_url]
    settings.sp_entity_id                   = Doubtfire::Application.config.saml[:entity_id]
    settings.idp_sso_target_url             = Doubtfire::Application.config.saml[:idp_sso_target_url]
    settings.idp_slo_target_url             = Doubtfire::Application.config.saml[:idp_sso_target_url]

    settings
  end

  #
  # Returns true if using SAML2.0 auth strategy
  #
  def saml_auth?
    Doubtfire::Application.config.auth_method == :saml
  end

  #
  # Returns true if using AAF devise auth strategy
  #
  def aaf_auth?
    Doubtfire::Application.config.auth_method == :aaf
  end

  #
  # Returns true if using LDAP devise auth strategy
  #
  def ldap_auth?
    Doubtfire::Application.config.auth_method == :ldap
  end

  #
  # Returns true if using database devise auth strategy
  #
  def db_auth?
    Doubtfire::Application.config.auth_method == :database
  end

  # ===========================================================================
  # Keycloak OIDC helpers — used for Google account linking and sign-in.
  # Independent of auth_method; active whenever DF_KEYCLOAK_URL is set.
  # ===========================================================================

  #
  # Returns true if Keycloak OIDC is configured
  #
  def keycloak_enabled?
    Doubtfire::Application.config.respond_to?(:keycloak) &&
      Doubtfire::Application.config.keycloak.present?
  end

  #
  # Shorthand accessor for the Keycloak config hash
  #
  def keycloak_config
    Doubtfire::Application.config.keycloak
  end

  #
  # Base URL for Keycloak OIDC endpoints (server-to-server, uses container name)
  #
  def keycloak_oidc_base
    "#{keycloak_config[:url]}/realms/#{keycloak_config[:realm]}/protocol/openid-connect"
  end

  #
  # Builds the Keycloak OIDC authorization URL to redirect the browser to.
  # kc_idp_hint=google tells Keycloak to skip its login page and go straight to Google.
  #
  def keycloak_auth_url(redirect_uri:, state:)
    # To force the Google account picker even when the user already has an active Google
    # session, add "&prompt=select_account" before the redirect_uri param.
    "#{keycloak_config[:public_url]}/realms/#{keycloak_config[:realm]}/protocol/openid-connect/auth" \
    "?client_id=#{keycloak_config[:client_id]}" \
    "&response_type=code" \
    "&scope=openid+email+profile" \
    "&kc_idp_hint=google" \
    "&redirect_uri=#{CGI.escape(redirect_uri)}" \
    "&state=#{CGI.escape(state)}"
  end

  #
  # Exchanges an authorization code for tokens via Keycloak's token endpoint.
  # This is a server-to-server call — the browser never sees the client_secret.
  # Returns the parsed JSON response hash, or nil on failure.
  #
  def exchange_keycloak_code(code:, redirect_uri:)
    uri = URI("#{keycloak_oidc_base}/token")
    response = Net::HTTP.post_form(uri, {
      grant_type:    'authorization_code',
      code:          code,
      redirect_uri:  redirect_uri,
      client_id:     keycloak_config[:client_id],
      client_secret: keycloak_config[:client_secret]
    })
    JSON.parse(response.body)
  rescue StandardError => e
    Rails.logger.error "Keycloak token exchange failed: #{e.message}"
    nil
  end

  #
  # Fetches Keycloak's public JWKS and verifies an ID token JWT.
  # Returns the decoded claims hash, or nil if verification fails.
  #
  def verify_keycloak_id_token(id_token)
    jwks_uri = URI("#{keycloak_oidc_base}/certs") 
    jwks_response = Net::HTTP.get(jwks_uri)
    jwks = JSON::JWK::Set.new(JSON.parse(jwks_response))
    JSON::JWT.decode(id_token, jwks)
  rescue JSON::JWT::Exception => e
    Rails.logger.error "Keycloak JWT verification failed: #{e.message}"
    nil
  rescue StandardError => e
    Rails.logger.error "Keycloak JWKS fetch failed: #{e.message}"
    nil
  end

  #
  # Generates a short-lived signed state JWT for OAuth2 CSRF protection.
  # mode: "link" carries user_id; mode: "signin" carries no user identity.
  #
  def generate_oauth_state(mode:, user_id: nil)
    payload = {
      mode:    mode,
      user_id: user_id,
      jti:     SecureRandom.hex(16),
      exp:     Time.zone.now.to_i + 300
    }
    JSON::JWT.new(payload).sign(
      Doubtfire::Application.credentials.secret_key_base, :HS256
    ).to_s
  end

  #
  # Decodes and verifies a state JWT. Returns the claims hash or nil if invalid.
  #
  def verify_oauth_state(state)
    JSON::JWT.decode(state, Doubtfire::Application.credentials.secret_key_base)
  rescue JSON::JWT::Exception
    nil
  end
end
