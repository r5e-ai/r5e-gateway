defmodule Mix.Tasks.Recurse.Provenance.VerifyTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Recurse.Provenance.Verify

  @cases Path.expand("vectors/cases", __DIR__)

  setup do
    shell = Mix.shell()
    Mix.shell(Mix.Shell.IO)
    on_exit(fn -> Mix.shell(shell) end)
  end

  defp trusted(name) do
    [@cases, name, "case.json"]
    |> Path.join()
    |> File.read!()
    |> Jason.decode!()
    |> then(fn settings ->
      Enum.flat_map(settings["trustedProfiles"], &["--trust", &1]) ++
        Enum.flat_map(settings["trustedPublishers"], &["--publisher", &1])
    end)
  end

  @tag :tmp_dir
  test "a sound bundle prints its summary, writes the report and returns", %{tmp_dir: dir} do
    name = "valid-sealed-stream"
    report = Path.join(dir, "report.json")
    bundle = Path.join([@cases, name, "bundle.json"])

    output = capture_io(fn -> Verify.run([bundle, "--report", report] ++ trusted(name)) end)

    assert output =~ "0 failed, 0 could not be checked"

    expected = [@cases, name, "expected-report.json"] |> Path.join() |> File.read!()
    assert Jason.decode!(File.read!(report)) == Jason.decode!(expected)
  end

  test "a bundle with a failed check exits 1 and names the check" do
    name = "bad-signature"
    bundle = Path.join([@cases, name, "bundle.json"])

    output =
      capture_io(fn ->
        assert catch_exit(Verify.run([bundle] ++ trusted(name))) == {:shutdown, 1}
      end)

    assert output =~ "failed  layer 1  signature  bad_signature"
  end

  test "a check that could not be performed exits 3, unless the reader accepts it" do
    bundle = Path.join([@cases, "valid-single-record-ed25519", "bundle.json"])

    output =
      capture_io(fn -> assert catch_exit(Verify.run([bundle])) == {:shutdown, 3} end)

    assert output =~ "incomplete  layer 2  authority  profile_not_trusted"

    accepted = capture_io(fn -> Verify.run([bundle, "--allow-incomplete"]) end)
    assert accepted =~ "incomplete  layer 2  authority  profile_not_trusted"
  end

  @tag :tmp_dir
  test "a file that is not JSON exits 2", %{tmp_dir: dir} do
    path = Path.join(dir, "not.json")
    File.write!(path, "not json")

    capture_io(:stderr, fn ->
      assert catch_exit(Verify.run([path])) == {:shutdown, 2}
    end)
  end
end
