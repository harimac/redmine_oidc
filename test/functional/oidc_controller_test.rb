require File.expand_path('test/test_helper', Dir.pwd)

class OidcControllerTest < Redmine::ControllerTest
  tests OidcController

  def setup
    super
    User.current = nil
    Setting.plugin_redmine_oidc = {
      'issuer_url' => 'http://issuer.example',
      'client_identifier' => 'redmine-oidc',
      'client_secret' => 'redmine-secret',
      'scopes' => 'openid email profile',
      'button_label' => 'Sign in with OIDC',
      'oidc_auto_login' => '0',
      'oidc_primary_login' => '0',
      'auto_registration' => '0',
      'email_matching' => '1'
    }
    OidcUserLink.delete_all
  end

  def test_callback_updates_last_login_and_sudo_timestamp_for_oidc_login
    user = User.find(2)
    user.update_column(:last_login_on, nil)

    RedmineOidc::OidcClient.any_instance.stubs(:exchange_code).returns('access_token' => 'access-token')
    RedmineOidc::OidcClient.any_instance.stubs(:userinfo).returns(
      'sub' => 'oidc-subject',
      'email' => user.mail
    )
    RedmineOidc::OidcClient.any_instance.stubs(:issuer_url).returns('http://issuer.example')

    @request.session[:oidc_state] = 'expected-state'

    get :callback, params: {code: 'auth-code', state: 'expected-state'}

    assert_redirected_to '/my/page'
    assert_equal user.id, @request.session[:user_id]
    assert_not_nil user.reload.last_login_on
    assert_not_nil @request.session[:sudo_timestamp]

    link = OidcUserLink.find_by(user_id: user.id)
    assert_equal 'http://issuer.example', link.issuer
    assert_equal 'oidc-subject', link.uid
  end

  def test_callback_redirects_to_local_login_bypass_when_auto_login_is_enabled
    Setting.plugin_redmine_oidc = Setting.plugin_redmine_oidc.merge('oidc_auto_login' => '1')
    @request.session[:oidc_state] = 'expected-state'
    @request.session[:oidc_back_url] = '/issues'

    get :callback, params: {code: 'auth-code', state: 'wrong-state'}

    assert_redirected_to '/login?back_url=%2Fissues&local_login=1'
    assert_equal ::I18n.t(:oidc_error_invalid_state), flash[:error]
  end

  def test_entra_registration_uses_verified_preferred_username_not_email_or_userinfo
    entra_callback(email: 'different@example.net', preferred_username: 'new.employee@example.org')
    assert_difference 'User.count', 1 do
      assert_difference 'OidcUserLink.count', 1 do
        get :callback, params: {code: 'auth-code', state: 'expected-state'}
      end
    end
    user = User.find_by_login('new.employee')
    assert_equal 'different@example.net', user.mail
    assert_equal user.id, @request.session[:user_id]
    assert_redirected_to '/my/page'
  end

  def test_email_matching_precedes_conflicting_preferred_username
    user = User.find(2)
    other = User.find(3)
    entra_callback(email: user.mail, preferred_username: "#{other.login}@example.org")
    assert_no_difference 'User.count' do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_equal user.id, @request.session[:user_id]
    assert_equal user.id, OidcUserLink.find_by(uid: 'entra-subject').user_id
    assert_equal user.login, user.reload.login
  end

  def test_same_login_and_email_auto_links_existing_user
    user = User.find(2)
    entra_callback(email: user.mail, preferred_username: "#{user.login}@example.org")
    assert_no_difference 'User.count' do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_equal user.id, @request.session[:user_id]
    assert_equal user.id, OidcUserLink.find_by(uid: 'entra-subject').user_id
  end

  def test_duplicate_login_with_different_email_stops_registration
    user = User.find(2)
    entra_callback(email: 'different@example.net', preferred_username: "#{user.login.upcase}@example.org")
    assert_no_difference ['User.count', 'OidcUserLink.count'] do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_redirected_to '/login'
    assert_equal ::I18n.t(:oidc_error_login_taken), flash[:error]
    assert_nil @request.session[:user_id]
  end

  def test_existing_oidc_link_precedes_email_and_new_login
    user = User.find(2)
    entra_callback(email: User.find(3).mail, preferred_username: nil)
    OidcUserLink.create!(user: user, issuer: entra_issuer, uid: 'entra-subject')
    assert_no_difference ['User.count', 'OidcUserLink.count'] do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_equal user.id, @request.session[:user_id]
  end

  def test_missing_preferred_username_does_not_fall_back_to_email
    entra_callback(email: 'different@example.net', preferred_username: nil)
    assert_no_difference ['User.count', 'OidcUserLink.count'] do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_equal ::I18n.t(:oidc_error_invalid_preferred_username), flash[:error]
  end

  def test_email_matching_can_still_be_disabled
    user = User.find(2)
    entra_callback(email: user.mail, preferred_username: "#{user.login}@example.org")
    Setting.plugin_redmine_oidc = Setting.plugin_redmine_oidc.merge('email_matching' => '0')
    assert_no_difference ['User.count', 'OidcUserLink.count'] do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_equal ::I18n.t(:oidc_error_login_taken), flash[:error]
  end

  def test_subject_mismatch_does_not_create_user_or_link
    entra_callback(email: 'different@example.net', preferred_username: 'new.employee@example.org', subject: 'wrong-subject')
    assert_no_difference ['User.count', 'OidcUserLink.count'] do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_equal ::I18n.t(:oidc_error_callback_failed), flash[:error]
  end

  def test_invalid_id_token_does_not_auto_link_email_match
    entra_callback(email: User.find(2).mail, preferred_username: 'employee@example.org')
    RedmineOidc::OidcClient.any_instance.stubs(:verified_id_token).raises(JWT::DecodeError)
    assert_no_difference ['User.count', 'OidcUserLink.count'] do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_equal ::I18n.t(:oidc_error_callback_failed), flash[:error]
    assert_nil @request.session[:user_id]
    assert_nil @request.session[:oidc_nonce]
  end

  def test_registration_rolls_back_when_link_cannot_be_saved
    entra_callback(email: 'different@example.net', preferred_username: 'new.employee@example.org')
    OidcUserLink.stubs(:create!).raises(ActiveRecord::RecordInvalid.new(OidcUserLink.new))
    assert_no_difference ['User.count', 'OidcUserLink.count'] do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_equal ::I18n.t(:oidc_error_auto_register_failed), flash[:error]
  end

  def test_invalid_or_overlong_preferred_username_is_not_rewritten
    ['@example.org', 'employee', "#{'a' * (User::LOGIN_LENGTH_LIMIT + 1)}@example.org", 'bad/name@example.org'].each do |name|
      entra_callback(email: 'different@example.net', preferred_username: name)
      assert_no_difference ['User.count', 'OidcUserLink.count'] do
        get :callback, params: {code: 'auth-code', state: 'expected-state'}
      end
      assert_redirected_to '/login'
      assert_not_nil flash[:error]
    end
  end

  def test_generic_provider_keeps_email_based_login_and_suffix
    user = User.find(2)
    Setting.plugin_redmine_oidc = Setting.plugin_redmine_oidc.merge('auto_registration' => '1')
    RedmineOidc::OidcClient.any_instance.stubs(:exchange_code).returns('access_token' => 'access-token')
    RedmineOidc::OidcClient.any_instance.stubs(:userinfo).returns(
      'sub' => 'generic-subject', 'email' => "#{user.login}@different.example.net",
      'preferred_username' => 'ignored@example.org')
    RedmineOidc::OidcClient.any_instance.expects(:verified_id_token).never
    @request.session[:oidc_state] = 'expected-state'
    assert_difference 'User.count', 1 do
      get :callback, params: {code: 'auth-code', state: 'expected-state'}
    end
    assert_equal "#{user.login}1", User.find(@request.session[:user_id]).login
  end

  private

  def entra_issuer
    'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0'
  end

  def entra_callback(email:, preferred_username:, subject: 'entra-subject')
    Setting.plugin_redmine_oidc = Setting.plugin_redmine_oidc.merge(
      'issuer_url' => entra_issuer, 'auto_registration' => '1')
    RedmineOidc::OidcClient.any_instance.stubs(:exchange_code).returns(
      'access_token' => 'access-token', 'id_token' => 'signed-id-token')
    RedmineOidc::OidcClient.any_instance.stubs(:userinfo).returns(
      'sub' => 'entra-subject', 'email' => email, 'preferred_username' => 'untrusted@example.org')
    RedmineOidc::OidcClient.any_instance.stubs(:verified_id_token).
      with('signed-id-token', nonce: 'expected-nonce').returns(
        'sub' => subject, 'preferred_username' => preferred_username)
    @request.session[:oidc_state] = 'expected-state'
    @request.session[:oidc_nonce] = 'expected-nonce'
  end
end
