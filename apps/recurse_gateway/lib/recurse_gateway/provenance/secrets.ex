defmodule Recurse.Gateway.Provenance.Secrets do
  @moduledoc """
  Looks through content for things that look like secrets, before that
  content is provided to anyone outside the deployment.

  It is a filter and not a guarantee. It knows a fixed set of shapes:
  private keys, the tokens of well-known providers, bearer headers, and
  `name = value` where the name says the value is secret. A secret in a
  shape it does not know passes. What it reports is only ever a reason to
  withhold; a clean result is never recorded as "contains no secrets".

  Content too large to look through, or not text, is reported as not
  scanned, and the caller withholds it.
  """

  @largest 8_388_608

  # Every repetition next to another is bounded, so no input makes a rule
  # take time out of proportion to its length. Quotes may be escaped
  # (`\\"`), because much recorded content is JSON carried inside JSON.
  @rules [
    {"private-key", ~r/-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----/},
    {"anthropic-token", ~r/\bsk-ant-[A-Za-z0-9_-]{16,}/},
    {"openai-token", ~r/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/},
    {"github-token", ~r/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})/},
    {"aws-access-key", ~r/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/},
    {"google-api-key", ~r/\bAIza[A-Za-z0-9_-]{35}\b/},
    {"slack-token", ~r/\bxox[abposr]-[A-Za-z0-9-]{10,}/},
    {"stripe-key", ~r/\b[sr]k_live_[A-Za-z0-9]{16,}/},
    {"json-web-token", ~r/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/},
    {"credentials-in-address",
     ~r/\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s\/:@"'\\]{1,128}:[^\s\/@"'\\]{1,256}@/i},
    {"authorization-header",
     ~r/\b(?:authorization|x-api-key)\\?["']?\s{0,8}[:=]\s{0,8}\\?["']?(?:(?:bearer|basic)\s{1,8})?[A-Za-z0-9._~+\/=-]{16,}/i},
    {"named-secret",
     ~r/(?:secret|passwd|password|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token)[a-z0-9_.-]{0,64}\\?["']?\s{0,8}[:=]\s{0,8}(?:\\?"[^"\\]{8,}|\\?'[^'\\]{8,}|[^\s"',;\\]{8,})/i}
  ]

  @doc "The names of the rules, in the order they are tried."
  @spec rules() :: [String.t()]
  def rules, do: Enum.map(@rules, &elem(&1, 0))

  @doc """
  Look through `bytes`. `:clean` when no rule matched, `{:flagged, names}`
  with the rules that did, or `:not_scanned` when the content is too
  large or is not text.
  """
  @spec scan(binary()) :: :clean | {:flagged, [String.t()]} | :not_scanned
  def scan(bytes) when is_binary(bytes) and byte_size(bytes) <= @largest do
    if String.valid?(bytes) do
      case for {name, rule} <- @rules, Regex.match?(rule, bytes), do: name do
        [] -> :clean
        names -> {:flagged, names}
      end
    else
      :not_scanned
    end
  end

  def scan(_too_large_or_not_binary), do: :not_scanned
end
