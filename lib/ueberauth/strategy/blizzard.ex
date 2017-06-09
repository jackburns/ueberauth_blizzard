defmodule Ueberauth.Strategy.Blizzard do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with Blizzard.
  ### Setup
  Create an application in Blizzard for you to use.
  Register a new application at: [Blizzard developer page](https://dev.battle.net) and get the `client_id` and `client_secret`.
  Include the provider in your configuration for Ueberauth
      config :ueberauth, Ueberauth,
        providers: [
          github: { Ueberauth.Strategy.Github, [] }
        ]
  Then include the configuration for Blizzard.
      config :ueberauth, Ueberauth.Strategy.Blizzard.OAuth,
        client_id: System.get_env("BLIZZARD_CLIENT_ID"),
        client_secret: System.get_env("BLIZZARD_CLIENT_SECRET")
  If you haven't already, create a pipeline and setup routes for your callback handler
      pipeline :auth do
        Ueberauth.plug "/auth"
      end
      scope "/auth" do
        pipe_through [:browser, :auth]
        get "/:provider/callback", AuthController, :callback
      end
  Create an endpoint for the callback where you will handle the `Ueberauth.Auth` struct
      defmodule MyApp.AuthController do
        use MyApp.Web, :controller
        def callback_phase(%{ assigns: %{ ueberauth_failure: fails } } = conn, _params) do
          # do things with the failure
        end
        def callback_phase(%{ assigns: %{ ueberauth_auth: auth } } = conn, params) do
          # do things with the auth
        end
      end
  You can edit the behaviour of the Strategy by including some options when you register your provider.
  To set the `uid_field`
      config :ueberauth, Ueberauth,
        providers: [
          github: { Ueberauth.Strategy.Blizzard, [uid_field: :battletag] }
        ]
  Default is "user,public_repo"
  """
  use Ueberauth.Strategy, uid_field: :id,
                          oauth2_module: Ueberauth.Strategy.Blizzard.OAuth,
                          default_region: "us"

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles the initial redirect to the Blizzard authentication page.
  To customize the scope (permissions) that are requested by Blizzard include them as part of your url:
      "?scope=user,sc2_profile,wow_profile"
  You can also include a `state` param that Blizzard will return to you.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    region = conn.params["region"] || option(conn, :default_region)
    IO.puts callback_url(conn)
    opts = [redirect_uri: callback_url(conn), scope: scopes]

    opts =
      if conn.params["state"], do: Keyword.put(opts, :state, conn.params["state"]), else: opts

    module = option(conn, :oauth2_module)

    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  @doc """
  Handles the callback from Blizzard. When there is a failure from Blizzard the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned from Blizzard is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)
    opts = [redirect_uri: callback_url(conn)]

    token = apply(module, :get_token!, [[code: code], opts])

    if token.access_token == nil do
      set_errors!(conn, [error(token.other_params["error"], token.other_params["error_description"])])
    else
      fetch_user(conn, token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw Blizzard response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:blizzard_user, nil)
    |> put_private(:blizzard_token, nil)
  end

  @doc """
  Fetches the uid field from the Blizzard response. This defaults to the option `uid_field` which in-turn defaults to `id`
  """
  def uid(conn) do
    user =
      conn
      |> option(:uid_field)
      |> to_string
    conn.private.blizzard_user[user]
  end

  @doc """
  Includes the credentials from the Blizzard response.
  """
  def credentials(conn) do
    token        = conn.private.blizzard_token
    scope_string = (token.other_params["scope"] || "")
    scopes       = String.split(scope_string, ",")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.blizzard_user

    %{ battletag: user["battletag"] }
  end

  @doc """
  Stores the raw information (including the token) obtained from the Blizzard callback.
  """
  def extra(conn) do
    %Extra {
      raw_info: %{
        token: conn.private.blizzard_token,
        user: conn.private.blizzard_user
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :blizzard_token, token)

    mashery_host = Ueberauth.Strategy.Blizzard.OAuth.get_api_host("us")
    case Ueberauth.Strategy.Blizzard.OAuth.get(token, mashery_host <> "/account/user") do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %OAuth2.Response{status_code: status_code, body: user}} when status_code in 200..399 ->
        put_private(conn, :blizzard_user, user)
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end