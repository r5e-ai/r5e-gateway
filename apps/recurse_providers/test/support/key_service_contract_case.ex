defmodule Recurse.Providers.KeyServiceContractSuite do
  @moduledoc """
  Shared `Recurse.Providers.KeyService` contract suite executed identically
  against `LocalKeyService`, `FakeKeyService`, `OpenBaoTransitKeyService`, and
  `GcpKmsKeyService`.
  """

  import ExUnit.Assertions

  defmacro __using__(opts) do
    impl = Keyword.fetch!(opts, :impl)

    quote do
      alias Recurse.Providers.KeyService
      alias Recurse.Providers.KeyServiceContractSuite

      @contract_impl unquote(impl)

      describe "KeyService contract (#{inspect(unquote(impl))})" do
        test "declares @behaviour Recurse.Providers.KeyService" do
          behaviours = @contract_impl.__info__(:attributes)[:behaviour] || []
          assert KeyService in behaviours
        end

        test "wraps and unwraps a 32-byte key under matching context", context do
          KeyServiceContractSuite.assert_round_trip(@contract_impl, build_service(context))
        end

        test "produces distinct non-plaintext ciphertexts on repeated wraps", context do
          KeyServiceContractSuite.assert_randomized_wrapping(
            @contract_impl,
            build_service(context)
          )
        end

        test "refuses unwrap when context does not match", context do
          KeyServiceContractSuite.assert_context_binding(@contract_impl, build_service(context))
        end

        test "refuses unwrap on corrupted or malformed ciphertexts", context do
          KeyServiceContractSuite.assert_corruption_rejected(
            @contract_impl,
            build_service(context)
          )
        end

        test "describe/1 returns an operator-readable label", context do
          label = @contract_impl.describe(build_service(context))
          assert is_binary(label) and byte_size(label) > 0
        end
      end
    end
  end

  def assert_round_trip(impl, state) do
    dek = :crypto.strong_rand_bytes(32)
    context = "session:01J8CONTRACTROUNDTRIP0001"

    assert {:ok, wrapped} = impl.wrap(state, dek, context)
    assert is_binary(wrapped) and byte_size(wrapped) > 0
    assert {:ok, ^dek} = impl.unwrap(state, wrapped, context)
  end

  def assert_randomized_wrapping(impl, state) do
    dek = :crypto.strong_rand_bytes(32)
    context = "session:01J8CONTRACTRANDOM000002"

    assert {:ok, wrapped_a} = impl.wrap(state, dek, context)
    assert {:ok, wrapped_b} = impl.wrap(state, dek, context)
    assert wrapped_a != wrapped_b
    refute :binary.match(wrapped_a, dek) != :nomatch
    refute :binary.match(wrapped_a, Base.encode64(dek)) != :nomatch
    assert {:ok, ^dek} = impl.unwrap(state, wrapped_a, context)
    assert {:ok, ^dek} = impl.unwrap(state, wrapped_b, context)
  end

  def assert_context_binding(impl, state) do
    dek = :crypto.strong_rand_bytes(32)

    assert {:ok, wrapped} = impl.wrap(state, dek, "session:alpha")
    assert {:error, :not_unwrappable} = impl.unwrap(state, wrapped, "session:beta")
    assert {:error, :not_unwrappable} = impl.unwrap(state, wrapped, "")
    assert {:ok, ^dek} = impl.unwrap(state, wrapped, "session:alpha")
  end

  def assert_corruption_rejected(impl, state) do
    dek = :crypto.strong_rand_bytes(32)
    context = "session:01J8CONTRACTCORRUPT00003"

    assert {:ok, wrapped} = impl.wrap(state, dek, context)
    corrupted_tail = flip_last_byte(wrapped)
    invalid_utf8 = <<0xFF, 0xFE, 0x00, 0x89, 1, 2, 3, 4>>

    assert {:error, :not_unwrappable} = impl.unwrap(state, corrupted_tail, context)
    assert {:error, :not_unwrappable} = impl.unwrap(state, invalid_utf8, context)
    assert {:error, :not_unwrappable} = impl.unwrap(state, "", context)
    assert {:error, :not_unwrappable} = impl.unwrap(state, "not-a-valid-envelope", context)
  end

  defp flip_last_byte(binary) do
    prefix_size = byte_size(binary) - 1
    <<prefix::binary-size(prefix_size), last>> = binary
    <<prefix::binary, Bitwise.bxor(last, 0x01)>>
  end
end
