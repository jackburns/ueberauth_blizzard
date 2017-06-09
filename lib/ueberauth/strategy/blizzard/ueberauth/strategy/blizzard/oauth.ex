defmodule Ueberauth.Strategy.Blizzard.OAuth do
  @moduledoc """
  An implementation of OAuth2 for Blizzard Battle.net.
  To add your `client_id` and `client_secret` include these values in your configuration.
      config :ueberauth, Ueberauth.Strategy.Blizzard.OAuth,
        client_id: System.get_env("BLIZZARD_CLIENT_ID"),
        client_secret: System.get_env("BLIZZARD_CLIENT_SECRET")
  """
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "https://battle.net",
    authorize_url: "https://blizzard.com/login/oauth/authorize",
    token_url: "https://blizzard.com/login/oauth/access_token",
  ]

  def get_host(region) do
    if region == "cn" do
      "https://www.battlenet.com.cn"
    else
      "https://" <> region <> ".battle.net"
    end
  end

  def get_api_host(region) do
    if region == "cn" do
      "https://api.battlenet.com.cn"
    else
      "https://" <> region <> ".api.battle.net"
    end
  end

  @doc """
  Construct a client for requests to Blizzard.
  Optionally include any OAuth2 options here to be merged with the defaults.
      Ueberauth.Strategy.Blizzard.OAuth.client(redirect_uri: "http://localhost:4000/auth/blizzard/callback")
  This will be setup automatically for you in `Ueberauth.Strategy.Blizzard`.
  These options are only useful for usage outside the normal callback phase of Ueberauth.
  """
  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.Blizzard.OAuth)
    host = get_host("us")
    opts = [authorize_url: host <> "/oauth/authorize", token_url: host <> "/oauth/token"] ++ opts

    client_opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    OAuth2.Client.new(client_opts)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth. No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get(token, url, headers \\ [], opts \\ []) do
    [token: token]
    |> client
    |> put_param("client_secret", client().client_secret)
    |> OAuth2.Client.get(url, headers, opts)
  end

  def get_token!(params \\ [], options \\ []) do
    client =
      options
      |> client
      |> OAuth2.Client.get_token!(params)
    client.token
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param("client_secret", client.client_secret)
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end
end