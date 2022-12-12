module OmniAuth
  module Strategies
    class Doorkeeper < OmniAuth::Strategies::OAuth2
      option :name, :doorkeeper

      option :client_options,
             site: ENV["DOORKEEPER_APP_URL"],
             authorize_path: "/oauth/authorize",
             connection_opts: {
               headers: {
                 'Authorization' => "Basic #{ENV["BASIC_AUTHORIZATION_TOKEN"]}"
               }
             }

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
        access_token_basic_auth = ::OAuth2::AccessToken.from_hash(access_token.client, { access_token: ENV["BASIC_AUTHORIZATION_TOKEN"], header_format: 'Basic %s' })
        @raw_info ||= access_token_basic_auth.get("/user_info?access_token=#{access_token.token}").parsed
      end
    end
  end
end
