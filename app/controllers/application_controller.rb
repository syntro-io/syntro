class ApplicationController < ActionController::API
  include ActionController::Serialization
  include ActionController::HttpAuthentication::Token::ControllerMethods

  # Add a before_action to authenticate all requests.
  # Move this to subclassed controllers if you only
  # want to authenticate certain methods.
  before_action :authenticate, except: [:index_public]
  before_filter :throttle_token

  protected

  # Authenticate the user with token based authentication
  def authenticate
    authenticate_token || render_unauthorized
  end

  def authenticate_token
    authenticate_with_http_token do |token, _options|
      @current_user = User.find_by(api_key: token)
      @token        = token
    end
  end

  def render_unauthorized(realm = 'Application')
    headers['WWW-Authenticate'] = %(Token realm="#{realm.delete('"')}")
    render json: { message: 'Bad credentials' }, status: :unauthorized
  end

  def throttle_ip
    client_ip = request.env['REMOTE_ADDR']
    key = "count:#{client_ip}"
    count = REDIS.get(key)

    unless count
      REDIS.set(key, 0)
      REDIS.expire(key, THROTTLE_TIME_WINDOW)
      return true
    end

    if count.to_i >= THROTTLE_MAX_REQUESTS
      render json: { message: 'You have fired too many requests. Please wait for some time.' }, status: 429
      return
    end
    REDIS.incr(key)
    true
  end

  def throttle_token
    if @token.present?
      key = "count:#{@token}"
      count = REDIS.get(key)

      unless count
        REDIS.set(key, 0)
        REDIS.expire(key, THROTTLE_TIME_WINDOW)
        return true
      end

      if count.to_i >= THROTTLE_MAX_REQUESTS
        render json: { message: 'You have fired too many requests. Please wait for some time.' }, status: 429
        return
      end
      REDIS.incr(key)
      true
    else
      false
    end
  end
end
