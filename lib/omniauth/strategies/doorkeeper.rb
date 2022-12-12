module OmniAuth
  module Strategies
    class Doorkeeper < OmniAuth::Strategies::OAuth2
      option :name, :doorkeeper

      option :client_options,
             site: ENV["DOORKEEPER_APP_URL"],
             authorize_path: "/oauth/authorize"

      uid do
        raw_info["id"]
      end

      info do
        {
          email: raw_info["email"],
          name: raw_info["name"],
          extra: raw_info
        }
      end

      def raw_info
        # p @raw_info
        # p @raw_info['extra'] if @raw_info.present?
        @raw_info ||= access_token.get("/user_info").parsed
      end
    end
  end
end
