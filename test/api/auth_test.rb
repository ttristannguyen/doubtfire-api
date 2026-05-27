require 'test_helper'
require 'minitest/mock'
require 'uri'
require 'cgi'

class AuthTest < ActiveSupport::TestCase
  include Rack::Test::Methods
  include TestHelpers::AuthHelper
  include TestHelpers::JsonHelper

  def app
    Rails.application
  end

  def decoded_query_param(url, key)
    query = URI.parse(url).query
    CGI.parse(query).fetch(key).first
  end

  def assert_keycloak_state(state, expected_mode, expected_user_id = nil)
    claims = AuthenticationHelpers.verify_oauth_state(state)
    assert claims, 'Expected OAuth state JWT to verify'
    assert_equal expected_mode, claims['mode']
    assert_equal expected_user_id, claims['user_id'] if expected_user_id
    assert claims['exp'] > Time.zone.now.to_i
    assert claims['jti'].present?
  end

  def stub_keycloak_token_exchange(id_token = 'verified-id-token')
    stub_request(:post, 'http://keycloak.test/realms/doubtfire/protocol/openid-connect/token')
      .with(body: hash_including(
        'grant_type' => 'authorization_code',
        'client_id' => 'doubtfire-api',
        'client_secret' => 'test-client-secret'
      ))
      .to_return(
        status: 200,
        body: { id_token: id_token }.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  # Stubs the AuthenticationHelpers#verify_keycloak_id_token INSTANCE method so
  # that Grape endpoints (which call the private instance version via `helpers`)
  # receive the given claims hash instead of performing a real JWKS fetch.
  # Minitest's built-in `stub` only patches the module-level (singleton) method,
  # so we patch the module's instance method directly and restore on exit.
  def stub_keycloak_id_token(claims)
    original = AuthenticationHelpers.instance_method(:verify_keycloak_id_token)
    AuthenticationHelpers.send(:define_method, :verify_keycloak_id_token) { |_token| claims }
    yield
  ensure
    AuthenticationHelpers.send(:define_method, :verify_keycloak_id_token, original)
  end

  # --------------------------------------------------------------------------- #
  # --- Endpoint testing for:
  # ------- /api/auth.json
  # ------- POST PUT DELETE

  # --------------------------------------------------------------------------- #
  # POST tests

  def test_auth_method_exposes_keycloak_google_signin_when_configured
    get '/api/auth/method'

    assert_equal 200, last_response.status
    assert_equal true, last_response_body['google_signin_enabled']
  end

  def test_keycloak_google_signin_start_returns_google_broker_url
    get '/api/auth/google'

    assert_equal 200, last_response.status
    signin_url = last_response_body['signin_url']

    assert_match %r{\Ahttp://localhost:8080/realms/doubtfire/protocol/openid-connect/auth}, signin_url
    assert_equal 'doubtfire-api', decoded_query_param(signin_url, 'client_id')
    assert_equal 'code', decoded_query_param(signin_url, 'response_type')
    assert_equal 'google', decoded_query_param(signin_url, 'kc_idp_hint')
    assert_equal 'http://localhost:3000/api/auth/google/callback', decoded_query_param(signin_url, 'redirect_uri')
    assert_keycloak_state decoded_query_param(signin_url, 'state'), 'signin'
  end

  def test_keycloak_google_link_start_requires_authenticated_user_and_sets_link_state
    user = FactoryBot.create(:user)
    add_auth_header_for(user: user)

    get '/api/auth/link/google'

    assert_equal 200, last_response.status
    link_url = last_response_body['link_url']

    assert_match %r{\Ahttp://localhost:8080/realms/doubtfire/protocol/openid-connect/auth}, link_url
    assert_equal 'google', decoded_query_param(link_url, 'kc_idp_hint')
    assert_equal 'http://localhost:3000/api/auth/link/callback', decoded_query_param(link_url, 'redirect_uri')
    assert_keycloak_state decoded_query_param(link_url, 'state'), 'link', user.id
  end

  def test_keycloak_google_signin_callback_uses_linked_login_and_issues_one_time_token
    user = FactoryBot.create(:user, username: 'linked-google-user')
    UserLinkedLogin.create!(
      user: user,
      provider: 'google',
      provider_identifier: 'linked@example.com'
    )

    state = AuthenticationHelpers.generate_oauth_state(mode: 'signin')
    stub_keycloak_token_exchange
    stub_keycloak_id_token({ 'email' => 'linked@example.com' }) do
      get "/api/auth/google/callback?code=abc123&state=#{CGI.escape(state)}"
    end

    assert_equal 302, last_response.status
    redirect = last_response.headers['Location']
    assert_match %r{/sign_in\?}, redirect
    assert_equal user.username, decoded_query_param(redirect, 'username')

    login_token = decoded_query_param(redirect, 'authToken')
    assert user.token_for_text?(login_token, :login), 'Expected callback to create a temporary login token'
  end

  def test_keycloak_google_signin_callback_rejects_unlinked_google_account
    state = AuthenticationHelpers.generate_oauth_state(mode: 'signin')
    stub_keycloak_token_exchange
    stub_keycloak_id_token({ 'email' => 'unlinked@example.com' }) do
      get "/api/auth/google/callback?code=abc123&state=#{CGI.escape(state)}"
    end

    assert_equal 302, last_response.status
    redirect = last_response.headers['Location']
    assert_equal 'no_linked_account', decoded_query_param(redirect, 'error')
    refute UserLinkedLogin.exists?(provider: 'google', provider_identifier: 'unlinked@example.com')
  end

  def test_keycloak_google_link_callback_records_linked_login
    user = FactoryBot.create(:user)
    state = AuthenticationHelpers.generate_oauth_state(mode: 'link', user_id: user.id)
    stub_keycloak_token_exchange

    stub_keycloak_id_token({ 'email' => 'new-link@example.com' }) do
      get "/api/auth/link/callback?code=abc123&state=#{CGI.escape(state)}"
    end

    assert_equal 302, last_response.status
    assert_equal 'google', decoded_query_param(last_response.headers['Location'], 'linked')
    assert UserLinkedLogin.exists?(
      user: user,
      provider: 'google',
      provider_identifier: 'new-link@example.com'
    )
  end

  def test_keycloak_google_link_callback_rejects_provider_identifier_already_linked_elsewhere
    first_user = FactoryBot.create(:user)
    second_user = FactoryBot.create(:user)
    UserLinkedLogin.create!(
      user: first_user,
      provider: 'google',
      provider_identifier: 'existing-link@example.com'
    )
    state = AuthenticationHelpers.generate_oauth_state(mode: 'link', user_id: second_user.id)
    stub_keycloak_token_exchange

    stub_keycloak_id_token({ 'email' => 'existing-link@example.com' }) do
      get "/api/auth/link/callback?code=abc123&state=#{CGI.escape(state)}"
    end

    assert_equal 302, last_response.status
    assert_equal 'already_linked', decoded_query_param(last_response.headers['Location'], 'link_error')
    refute UserLinkedLogin.exists?(
      user: second_user,
      provider: 'google',
      provider_identifier: 'existing-link@example.com'
    )
  end

  # Test POST for new authentication token
  def test_auth_post
    data_to_post = {
      username: 'aadmin',
      password: 'password'
    }
    # Get response back for logging in with username 'aadmin' password 'password'
    post_json '/api/auth.json', data_to_post
    actual_auth = last_response_body
    expected_auth = User.first

    # Check that response contains a user.
    assert actual_auth.key?('user'), 'Expect response to have a user'
    assert actual_auth.key?('auth_token'), 'Expect response to have a auth token'

    response_user_data = actual_auth['user']

    # Check that the returned user has the required details.
    # These match the model object... so can compare in loops
    user_keys = %w(id email first_name last_name username nickname receive_task_notifications receive_portfolio_notifications receive_feedback_notifications opt_in_to_research has_run_first_time_setup)

    # Check the returned user matches the expected database value
    assert_json_matches_model(expected_auth, response_user_data, user_keys)

    # Check other values returned
    assert_equal expected_auth.role.name, response_user_data['system_role'], 'Roles match'

    token = User.first.token_for_text? actual_auth['auth_token'], :general
    assert token.present?
    assert_equal 'general', token.token_type

    # User has the token - count of matching tokens for that user is 1
    assert_equal 1, expected_auth.auth_tokens.select{|t| t.authentication_token == actual_auth['auth_token']}.count
  end

  # Test auth when username is invalid
  def test_fail_username_auth
    data_to_post = {
      username: 'aadmin123',
      password: 'password'
    }
    # Get response back for logging in with username 'aadmin' password 'password'
    post_json '/api/auth.json', data_to_post
    actual_auth = last_response_body

    # Check response body doesn't return 'user' and 'auth_token' values
    refute actual_auth.key?('user'), 'User not expected if auth fails'
    refute actual_auth.key?('auth_token'), 'Auth token not expected if auth fails'

    # 401 response code means invalid username / password
    assert_equal 401, last_response.status
    assert actual_auth.key? 'error'
  end

  # Test auth when password is invalid
  def test_fail_password_auth
    data_to_post = {
      username: 'aadmin',
      password: 'password1'
    }

    # Get response back for logging in with username 'aadmin' password 'password1'
    post_json '/api/auth.json', data_to_post
    actual_auth = last_response_body

    # Check response body doesn't return 'user' and 'auth_token' values
    refute actual_auth.key?('user'), 'User not expected if auth fails'
    refute actual_auth.key?('auth_token'), 'Auth token not expected if auth fails'

    assert actual_auth.key? 'error'
  end

  # Test auth with empty request body
  def test_fail_empty_request
    data_to_post = ""

    # Post empty data
    post_json '/api/auth.json', data_to_post
    actual_auth = last_response_body

    # Check response body doesn't return 'user' and 'auth_token' values
    refute actual_auth.key?('user'), 'User not expected if auth fails'
    refute actual_auth.key?('auth_token'), 'Auth token not expected if auth fails'

    # 400 response code means missing username and password
    assert_equal 400, last_response.status
    assert actual_auth.key?('error'), actual_auth.inspect
  end

  # Test auth with tutor role
  def test_auth_roles
    post_tests = [
      {
        expect: Role.admin,
        post: {
          username: 'aadmin',
          password: 'password'
        }
      },
      {
        expect: Role.convenor,
        post: {
          username: 'aconvenor',
          password: 'password'
        }
      },
      {
        expect: Role.tutor,
        post: {
          username: 'atutor',
          password: 'password'
        }
      },
      {
        expect: Role.student,
        post: {
          username: 'astudent',
          password: 'password'
        }
      }
    ]

    post_tests.each do |test_data|
      # Get response back for logging in with above data
      post_json '/api/auth.json', test_data[:post]
      actual_auth = last_response_body

      assert actual_auth['user'], last_response_body.inspect
      assert_equal test_data[:expect].name, actual_auth['user']['system_role'], 'Roles match expected role'
    end
  end

  # End POST tests
  # --------------------------------------------------------------------------- #

  # --------------------------------------------------------------------------- #
  # PUT tests

  # Test put for authentication token
  def test_auth_put
    add_auth_header_for(user: User.first)
    put_json "/api/auth", nil

    actual_auth = last_response_body['auth_token']
    expected_auth = auth_token
    # Check to see if the response auth token matches the auth token that was sent through in put
    assert_equal expected_auth, actual_auth
  end

  def test_auth_using_query_string
    put_json "/api/auth?Username=#{User.first.username}&Auth-Token=#{auth_token(User.first)}", nil
    assert_equal 200, last_response.status, last_response_body
  end

  # Test invalid authentication token
  def test_fail_auth_put
    # Override data to set custom username or token in header
    # Add authentication token to header
    add_auth_header_for(user: User.first, auth_token: '1234')
    put_json "/api/auth", nil
    actual_auth = last_response_body
    expected_auth = auth_token

    # 404 response code means invalid token
    assert_equal 404, last_response.status

    # Check to see if the response is invalid
    assert actual_auth.key? 'error'
  end

  # Test invalid username for valid authentication token
  def test_fail_username_put
    # Add authentication token to header
    add_auth_header_for(user: User.first, username: 'acain123')
    put_json "/api/auth", nil
    actual_auth = last_response_body
    expected_auth = auth_token

    # 404 response code means invalid token
    assert_equal 404, last_response.status

    # Check to see if the response is invalid
    assert actual_auth.key? 'error'
  end

  # Test valid username for empty authentication token
  def test_fail_empty_authKey_put
    # Add authentication token to header
    add_auth_header_for(user: User.first)

    # Overwrite header for empty auth_token
    header 'auth_token',''

    put_json "/api/auth/", nil
    actual_auth = last_response_body
    expected_auth = auth_token

    # 404 response code means invalid token
    assert_equal 404, last_response.status

    # Check to see if the response is invalid
    assert actual_auth.key? 'error'
  end

  # Test empty request
  def test_fail_empty_body_put
    put_json "/api/auth", nil
    actual_auth = last_response_body
    expected_auth = auth_token

    # 400 response code means empty body
    assert_equal 404, last_response.status

    # Check to see if the response is invalid
    assert actual_auth.key? 'error'
  end
  # # End PUT tests
  # # --------------------------------------------------------------------------- #

  # # --------------------------------------------------------------------------- #
  # # DELETE tests

  # Test for deleting authentication token
  def test_auth_delete
    # Add authentication token to header
    add_auth_header_for(user: User.first)

    delete "/api/auth", nil
    # 204 response code means success!
    assert_equal 204, last_response.status
  end

  def test_token_signout_works_with_multiple
    user = FactoryBot.create(:user)
    # Create 2 auth tokens
    t1 = user.generate_authentication_token!
    t2 = user.generate_authentication_token!

    # Set custom headers for request
    # Add authentication token to header
    add_auth_header_for(username: user.username, auth_token: t1.authentication_token)

    # Sign out one
    delete "/api/auth.json"

    t2.reload
    refute t2.destroyed?

    assert_raises(ActiveRecord::RecordNotFound) { t1.reload }
  end
  # End DELETE tests
  # --------------------------------------------------------------------------- #

  # # --------------------------------------------------------------------------- #
  # # SCORM auth test

  def test_scorm_auth
    admin = FactoryBot.create(:user, :admin)

    add_auth_header_for(user: admin)

    # All users can access scorm resources
    get "api/auth/scorm"
    assert_equal 200, last_response.status
    assert_equal 1, admin.auth_tokens.where(token_type: :scorm).count

    student = FactoryBot.create(:user, :student)

    student.auth_tokens.where(token_type: :scorm).destroy_all

    add_auth_header_for(user: student)

    # When user is authorised and no prior scorm tokens exist
    get "api/auth/scorm"
    assert_equal 200, last_response.status
    assert last_response_body["scorm_auth_token"]
    assert 2, student.auth_tokens.where(token_type: :scorm).count

    first_token = last_response_body["scorm_auth_token"]

    add_auth_header_for(user: student)

    # When previous valid scorm token exists
    get "api/auth/scorm"
    assert_equal 200, last_response.status
    assert last_response_body["scorm_auth_token"] == first_token

    old_token = student.auth_tokens.find_by(token_type: :scorm)
    old_token.auth_token_expiry = Time.zone.now - 1.day
    old_token.save!

    add_auth_header_for(user: student)

    # When previous expired scorm token exists
    get "api/auth/scorm"
    assert_equal 200, last_response.status
    assert last_response_body["scorm_auth_token"] != first_token
    assert_raises ActiveRecord::RecordNotFound do
      student.auth_tokens.find(old_token.id)
    end
  end

  # End SCORM auth test
  # --------------------------------------------------------------------------- #

  def test_login_token
    unit = FactoryBot.create :unit, with_students: false
    user = unit.main_convenor_user

    token = user.generate_temporary_authentication_token!

    add_auth_header_for(user: user, auth_token: token)

    get 'api/units'

    assert 403, last_response.status

    post 'api/auth'
  ensure
    unit.destroy
  end

  def test_scorm_token
    unit = FactoryBot.create :unit, with_students: false
    user = unit.main_convenor_user

    token = user.generate_scorm_authentication_token!

    add_auth_header_for(user: user, auth_token: token)

    get '/api/units'

    assert 403, last_response.status
  ensure
    unit.destroy
  end
end
