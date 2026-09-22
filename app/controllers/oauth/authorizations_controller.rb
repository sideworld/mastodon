# frozen_string_literal: true

class OAuth::AuthorizationsController < Doorkeeper::AuthorizationsController
  prepend_before_action :store_current_location

  layout 'modal'

  content_security_policy do |p|
    p.form_action(false)
  end

  include Localized

  private

  def store_current_location
    store_location_for(:user, request.url)
  end

  def can_authorize_response?
    !truthy_param?('force_login') && super
  end

  def truthy_param?(key)
    ActiveModel::Type::Boolean.new.cast(params[key])
  end

  def authenticate_resource_owner!
    if truthy_param?('signup') && !current_user
      session[:sign_up_app_id] = params[:client_id]

      return redirect_to(new_user_registration_path)
    end

    super
  end

  def after_successful_authorization(context)
    current_resource_owner.update(created_by_application_id: session[:sign_up_app_id]) if session[:sign_up_app_id] == context.pre_auth.client.id
  end

  def require_functional!
    super unless truthy_param?('signup')
  end

  def mfa_setup_path
    super({ oauth: true })
  end
end
