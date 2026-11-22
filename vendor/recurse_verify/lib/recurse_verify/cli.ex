defmodule RecurseVerify.CLI do
  @moduledoc """
  Escript entry point:

      recurse_verify PATH_TO_BUNDLE [--prior PATH]
                                    [--posture house|commons]
                                    [--trust KEY[=LABEL]]... [--trust-file PATH]

  Exit status: 0 no findings, 1 findings present, 2 unusable input. The
  text, not the exit code, is the verdict — see the output doctrine in
  this project's README.

  ## `--posture` is the reader's, and it is required when it matters

  Spec 011 §9: a bundle carrying an **admitted Badge** cannot be reported
  on without knowing whether the reader considers this a house (its own
  agents, its own fence) or a commons (a system governing people's
  participation in the world). The same chain is unremarkable in one and a
  finding in the other, and there is no default because guessing would
  make the tool answer a question it was not asked. The deployment's own
  `Deployment` declaration is printed beside the line and decides nothing.

  ## `--trust` is the reader's too

  Nothing on a chain says which root keys matter. A pin is how a reader
  says so for one run; it never comes from the bundle, and it never
  follows succession (`RecurseVerify.Trust`).
  """

  @options [prior: :string, posture: :string, trust: :keep, trust_file: :string]

  def main(args) do
    # A report is **bytes**, and an Erlang io device transcodes what it
    # is given according to an encoding it takes from the environment:
    # under a C locale the same report comes out with every non-ASCII
    # character mangled, and under a UTF-8 one it comes out
    # double-encoded. Either way the bytes a reader compares would depend
    # on the reader's shell rather than on the bundle, which spec/07 §3.2
    # does not allow. Both devices are put in byte mode once, here.
    :io.setopts(:standard_io, encoding: :latin1)
    :io.setopts(:standard_error, encoding: :latin1)

    {opts, positional, invalid} = OptionParser.parse(args, strict: @options)

    case {positional, invalid} do
      {[bundle], []} -> run(bundle, opts)
      _ -> usage()
    end
  end

  defp run(bundle, opts) do
    case RecurseVerify.Trust.load(Keyword.get_values(opts, :trust), opts[:trust_file]) do
      {:ok, pins} -> verify(bundle, opts, pins)
      {:error, message} -> fail(message)
    end
  end

  defp verify(bundle, opts, pins) do
    case RecurseVerify.run(bundle, prior: opts[:prior], posture: opts[:posture], trust: pins) do
      {:ok, report} ->
        write(:stdio, RecurseVerify.format(report))
        if report.findings != [], do: System.halt(1)

      {:error, message} ->
        fail(message)
    end
  end

  defp fail(message) do
    write(:standard_error, "recurse_verify: #{message}")
    System.halt(2)
  end

  defp usage do
    write(:standard_error, """
    usage: recurse_verify PATH_TO_BUNDLE [--prior PATH_TO_EARLIER_BUNDLE]
                                         [--posture house|commons]
                                         [--trust KEY[=LABEL]]... [--trust-file PATH]
    """)

    System.halt(2)
  end

  # `IO.puts/2` writes *characters*, and an Erlang io device's encoding
  # comes from the environment: under `LANG=""` or a C locale the same
  # report comes out with every non-ASCII character mangled — the section
  # signs and em dashes in a Kind's description, and in this tool's own
  # sentences. A report whose bytes depend on the reader's locale is not
  # a report two implementations can be compared on (spec/07 §3.2), so
  # the bytes are written as bytes. The trailing newline is the one
  # `IO.puts/2` used to add, and it is why standard output ends `\n\n`.
  defp write(device, text), do: IO.binwrite(device, [text, "\n"])
end
