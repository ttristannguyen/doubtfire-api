require 'onelogin/ruby-saml'
require 'keycloak_token_service'
require 'securerandom'

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
    return authenticate_with_keycloak if keycloak_auth?

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
    if keycloak_auth?
      request.env['keycloak.user']
    else
      username = headers['username'] || headers['Username'] || params['username']
      User.eager_load(:role, :auth_tokens).find_by(username: username)
    end
  end

  def authenticate_with_keycloak
    authorization_header = headers['Authorization'] || headers['authorization']
    error!({ error: 'Authorization header missing.' }, 401) if authorization_header.blank?

    scheme, token = authorization_header.split(' ')
    unless scheme&.casecmp('Bearer')&.zero? && token.present?
      error!({ error: 'Authorization header must use the Bearer scheme.' }, 401)
    end

    payload = KeycloakTokenService.instance.decode(token)
    user = find_or_create_user_from_keycloak(payload)

    request.env['keycloak.token'] = payload
    request.env['keycloak.user'] = user
    request.env['keycloak.roles'] = realm_roles_from_claims(payload)
    request.env['keycloak.token_string'] = token

    logger.info("Authenticated #{user.username} via Keycloak from #{request.ip}")
    true
  rescue KeycloakTokenService::VerificationError => e
    logger.warn("Keycloak authentication failed: #{e.message}")
    error!({ error: e.message }, e.status)
  end

  def find_or_create_user_from_keycloak(claims)
    email = claims[:email] || claims[:preferred_username]
    username = (claims[:preferred_username] || email)&.downcase
    subject = claims[:sub]

    if email.blank? || username.blank?
      raise KeycloakTokenService::VerificationError.new('Token missing required identity claims.', 401)
    end

    user = User.eager_load(:role).find_by(email: email.downcase) ||
           User.eager_load(:role).find_by(username: username) ||
           User.new

    given_name = claims[:given_name] || claims[:firstName] || user.first_name || 'First'
    family_name = claims[:family_name] || claims[:lastName] || user.last_name || 'User'

    user.first_name = given_name.titleize
    user.last_name = family_name.titleize
    user.email = email.downcase
    user.username ||= username
    user.nickname ||= claims[:preferred_username] || user.first_name
    user.login_id ||= subject || email
    user.role = map_role_from_claims(claims, user.role)

    if user.encrypted_password.blank?
      user.password = SecureRandom.hex(32)
    end

    if user.changed?
      begin
        user.save!
      rescue ActiveRecord::RecordInvalid => e
        raise KeycloakTokenService::VerificationError.new("Failed to persist Keycloak user profile: #{e.record.errors.full_messages.join(', ')}", 500)
      end
    end

    user
  end

  def map_role_from_claims(claims, current_role)
    roles = realm_roles_from_claims(claims)
    priority = {
      'admin' => Role.admin,
      'auditor' => Role.auditor,
      'convenor' => Role.convenor,
      'tutor' => Role.tutor,
      'student' => Role.student
    }

    matching_role = roles.find { |role| priority.key?(role) }
    return current_role || Role.student if matching_role.nil?

    priority[matching_role]
  rescue => e
    logger.warn("Failed to map Keycloak roles: #{e.message}")
    current_role || Role.student
  end

  def realm_roles_from_claims(claims)
    roles = Array(claims.dig(:realm_access, :roles))
    roles.map { |role| role.to_s.sub(/^realm:/, '') }
  end

  #
  # Add the required auth_token to each of the routes for the provided
  # Grape::API.
  #
  def add_auth_to(service)
    return service if keycloak_auth?

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
      settings = idp_metadata_parser.parse_remote(metadata_url)
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

  def keycloak_auth?
    Doubtfire::Application.config.auth_method == :keycloak
  end
end
