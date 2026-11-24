defmodule Recurse.Gateway.Personal.Policy do
  @moduledoc """
  Pure policy and admission guards for opt-in `personal.r5e.io/v1` households
  (`R5E_PERSONAL_ENABLED=true`).

  Enforces three critical security invariants:

    1. **Strict 5-Kind Child Device `Badge.kinds` Allowlist:** Child device
       badges may ONLY carry the closed set
       `personal.r5e.io/v1/ChildDevicePaired`,
       `personal.r5e.io/v1/SafetyIntervention`,
       `provenance.r5e.io/v2/ToolCall`,
       `provenance.r5e.io/v2/ToolResult`, and
       `provenance.r5e.io/v2/Observation`.
       Wildcards (`personal.r5e.io/v1/*`) and parent-only kinds
       (`FamilyGuardrailSet`, `HouseholdProfile`, `PersonalErasure`,
       `CoParentApproval`, `RecoveryCompleted`, `custody.r5e.io/v1/*`) fail
       closed with `{:error, :invalid_child_badge_kinds}`.
    2. **Two-Parent (`threshold: 2`) Household Erasure Gate:** On any
       household with `threshold >= 2`, `personal.r5e.io/v1/PersonalErasure`
       with `scope == "household"` requires an approved distinct-parent
       `coSignRef` (`409 co_sign_required`).
    3. **Proof-of-Possession on Child QR Pairing:** Verifies `es256` /
       `ed25519` PoP signatures over `"r5e.child-pairing-pop/v1:<id>:<nonce>"`.
  """

  alias Recurse.Provenance.{Envelope, Evidence, Key}
  alias Recurse.Providers.Personal, as: Store

  @child_badge_kinds [
    "personal.r5e.io/v1/ChildDevicePaired",
    "personal.r5e.io/v1/SafetyIntervention",
    "provenance.r5e.io/v2/ToolCall",
    "provenance.r5e.io/v2/ToolResult",
    "provenance.r5e.io/v2/Observation"
  ]

  @child_badge_kind_set MapSet.new(@child_badge_kinds)

  @doc "Whether `R5E_PERSONAL_ENABLED` is enabled."
  @spec enabled?() :: boolean()
  def enabled? do
    Application.get_env(:recurse_gateway, :personal_enabled?, false) == true
  end

  @doc "Closed 5-kind allowlist permitted on any child device `Badge.body.kinds`."
  @spec child_badge_kinds() :: [String.t()]
  def child_badge_kinds, do: @child_badge_kinds

  @doc """
  Validate that `kinds` is a non-empty list of exact strings drawn strictly
  from `child_badge_kinds/0` with zero wildcards (`*`) or parent-only kinds.
  """
  @spec validate_child_badge_kinds(term()) :: :ok | {:error, :invalid_child_badge_kinds}
  def validate_child_badge_kinds(kinds) when is_list(kinds) and kinds != [] do
    valid? =
      Enum.all?(kinds, fn kind ->
        is_binary(kind) and not String.contains?(kind, "*") and
          MapSet.member?(@child_badge_kind_set, kind)
      end)

    if valid?, do: :ok, else: {:error, :invalid_child_badge_kinds}
  end

  def validate_child_badge_kinds(_other), do: {:error, :invalid_child_badge_kinds}

  @doc """
  Verify a child device's QR pairing proof-of-possession signature over
  `"r5e.child-pairing-pop/v1:" <> challenge_id <> ":" <> nonce`.
  """
  @spec verify_pairing_pop(map(), String.t(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, :bad_pop_signature}
  def verify_pairing_pop(
        %{"algorithm" => alg, "bytes" => pub_b64},
        challenge_id,
        nonce,
        pop_sig_b64
      )
      when alg in ["es256", "ed25519"] and is_binary(pub_b64) and is_binary(pop_sig_b64) do
    message = "r5e.child-pairing-pop/v1:#{challenge_id}:#{nonce}"

    with {:ok, pub_bytes} <- Base.decode64(pub_b64),
         {:ok, sig_bytes} <- Base.decode64(pop_sig_b64),
         {:ok, key_id} <- Key.id(alg, pub_bytes),
         true <- verify_raw_sig(alg, pub_bytes, message, sig_bytes) do
      {:ok, key_id}
    else
      _ -> {:error, :bad_pop_signature}
    end
  end

  def verify_pairing_pop(_pub, _challenge_id, _nonce, _pop), do: {:error, :bad_pop_signature}

  @doc """
  Defense-in-depth admission guard invoked from `Admission.submit/2` when
  `R5E_PERSONAL_ENABLED=true`. Rejects:

    * any child device badge listing wildcards or parent-only kinds
      (`:invalid_child_badge_kinds`),
    * any record signed by a registered child device key outside the 5-kind
      allowlist (`:invalid_child_badge_kinds`),
    * any `personal.r5e.io/v1/PersonalErasure` with `scope: "household"` on a
      `threshold >= 2` household missing a verified approved `coSignRef`
      (`:co_sign_required`).
  """
  @spec check_admission_batch([map()], map() | nil) :: :ok | {:error, atom()}
  def check_admission_batch(opened_records, authority) do
    if enabled?() do
      with :ok <- check_child_authority_badges(authority),
           :ok <- check_records(opened_records) do
        :ok
      end
    else
      :ok
    end
  end

  defp check_child_authority_badges(%{"records" => records}) when is_list(records) do
    Enum.reduce_while(records, :ok, fn record, :ok ->
      case check_authority_badge_record(record) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp check_child_authority_badges(_), do: :ok

  defp check_authority_badge_record(%{"envelope" => env}) do
    with {:ok, %{evidence: %{"kind" => "Badge", "body" => body}}} <- Envelope.open(env),
         true <- child_badge_body?(body) do
      validate_child_badge_kinds(body["kinds"])
    else
      _ -> :ok
    end
  end

  defp check_authority_badge_record(_), do: :ok

  defp child_badge_body?(%{"subject" => subject} = body) when is_binary(subject) do
    child_workload? =
      is_binary(body["workload"]) and String.starts_with?(body["workload"], "child-device")

    child_role? = get_in(body, ["details", "role"]) == "child"

    child_workload? or child_role? or match?({:ok, _}, Store.get_child_device(subject))
  end

  defp child_badge_body?(_), do: false

  defp check_records(opened_records) do
    Enum.reduce_while(opened_records, :ok, fn %{evidence: evidence}, :ok ->
      with :ok <- check_child_device_record(evidence),
           :ok <- check_household_erasure_cosign(evidence) do
        {:cont, :ok}
      else
        error -> {:halt, error}
      end
    end)
  end

  defp check_child_device_record(%{"issuer" => issuer} = evidence) when is_binary(issuer) do
    case Store.get_child_device(issuer) do
      {:ok, %{revoked_at: revoked}} when not is_nil(revoked) ->
        {:error, :child_device_revoked}

      {:ok, _device} ->
        kind_path = Evidence.kind_path(evidence)

        if MapSet.member?(@child_badge_kind_set, kind_path),
          do: :ok,
          else: {:error, :invalid_child_badge_kinds}

      :not_found ->
        :ok
    end
  end

  defp check_child_device_record(_), do: :ok

  defp check_household_erasure_cosign(%{
         "apiVersion" => "personal.r5e.io/v1",
         "kind" => "PersonalErasure",
         "body" => %{"scope" => "household", "targetId" => household_id} = body
       })
       when is_binary(household_id) do
    case Store.get_household(household_id) do
      {:ok, %{threshold: threshold}} when threshold >= 2 ->
        if Store.approved_cosign?(household_id, "household", household_id, body["coSignRef"]) do
          :ok
        else
          {:error, :co_sign_required}
        end

      _ ->
        :ok
    end
  end

  defp check_household_erasure_cosign(_), do: :ok

  defp verify_raw_sig("ed25519", pub, message, sig) when byte_size(pub) == 32 do
    :crypto.verify(:eddsa, :none, message, sig, [pub, :ed25519])
  rescue
    _ -> false
  end

  defp verify_raw_sig("es256", pub, message, sig) when byte_size(pub) == 65 do
    # Accept raw IEEE P1363 (64 bytes r||s) or DER-encoded ECDSA signatures.
    der = if byte_size(sig) == 64, do: raw_es256_to_der(sig), else: sig
    :crypto.verify(:ecdsa, :sha256, message, der, [pub, :secp256r1])
  rescue
    _ -> false
  end

  defp verify_raw_sig(_alg, _pub, _message, _sig), do: false

  defp raw_es256_to_der(<<r::binary-size(32), s::binary-size(32)>>) do
    r_int = der_integer(r)
    s_int = der_integer(s)
    seq = r_int <> s_int
    <<0x30, byte_size(seq)>> <> seq
  end

  defp der_integer(bytes) do
    stripped =
      case :binary.decode_unsigned(bytes) do
        0 -> <<0>>
        n -> :binary.encode_unsigned(n)
      end

    padded =
      case stripped do
        <<first, _::binary>> when first >= 0x80 -> <<0, stripped::binary>>
        _ -> stripped
      end

    <<0x02, byte_size(padded)>> <> padded
  end
end
